<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Request inspection, IP allow/block rules, temporary auto-bans, and disk-backed
 * malicious request logging with zero MySQL overhead.
 */
final class RequestGuard {

    public const LOG_FILE = 'malicious-requests.jsonl';
    public const IP_RULES_FILE = 'ip-rules.json';
    public const BANS_FILE = 'auto-bans.json';
    public const STRIKES_FILE = 'ip-strikes.json';
    public const MAX_LOG_ENTRIES = 2000;

    private const SEVERITY_RANK = [
        'critical' => 4,
        'high'     => 3,
        'medium'   => 2,
        'low'      => 1,
    ];

    /**
     * Resolve effective WAF inspection mode ('monitor', 'block', or 'off').
     */
    public static function get_mode(): string {
        if (function_exists('get_option')) {
            $mode = strtolower(trim(Settings::get_string('waf_mode', '')));
            if (in_array($mode, ['monitor', 'block', 'off'], true)) {
                return $mode;
            }
            if (Settings::get_bool('waf_enabled', false)) {
                return 'block';
            }
            if (Settings::get_bool('request_logging', true)) {
                return 'monitor';
            }
            return 'off';
        }

        return 'monitor';
    }

    /**
     * Match an IPv4 or IPv6 address against an exact IP or CIDR rule via binary prefix comparison.
     */
    public static function ip_matches_cidr(string $ip, string $rule): bool {
        $ip   = trim($ip);
        $rule = trim($rule);
        if ('' === $ip || '' === $rule) {
            return false;
        }

        $ip_bin = @inet_pton($ip);
        if (false === $ip_bin) {
            return false;
        }

        if (!str_contains($rule, '/')) {
            $rule_bin = @inet_pton($rule);
            return false !== $rule_bin && $ip_bin === $rule_bin;
        }

        $parts = explode('/', $rule, 2);
        if (2 !== count($parts)) {
            return false;
        }
        [$net, $mask_str] = $parts;
        if (!ctype_digit($mask_str)) {
            return false;
        }

        $net_bin = @inet_pton($net);
        if (false === $net_bin || strlen($ip_bin) !== strlen($net_bin)) {
            return false;
        }

        $max_bits = strlen($ip_bin) * 8;
        $prefix   = (int) $mask_str;
        if ($prefix < 0 || $prefix > $max_bits) {
            return false;
        }
        if (0 === $prefix) {
            return true;
        }

        $full_bytes = intdiv($prefix, 8);
        $rem_bits   = $prefix % 8;

        if ($full_bytes > 0 && substr($ip_bin, 0, $full_bytes) !== substr($net_bin, 0, $full_bytes)) {
            return false;
        }

        if ($rem_bits > 0) {
            $mask_byte = (0xFF << (8 - $rem_bits)) & 0xFF;
            if ((ord($ip_bin[$full_bytes]) & $mask_byte) !== (ord($net_bin[$full_bytes]) & $mask_byte)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Load manual IP allowlist and blocklist rules from disk.
     *
     * @return array{allowlist:array<int,array<string,string>>,blocklist:array<int,array<string,string>>}
     */
    public static function get_ip_rules(?string $storage_dir = null): array {
        $storage = self::resolve_storage_dir($storage_dir);
        return self::read_ip_rules_unlocked($storage);
    }

    /**
     * Add or update an IP/CIDR entry in the allowlist or blocklist.
     *
     * @return array<string,mixed>
     */
    public static function add_ip_rule(string $ip_or_cidr, string $list, string $note = '', ?string $storage_dir = null): array {
        $ip_or_cidr = trim($ip_or_cidr);
        $list       = strtolower(trim($list));

        if (!in_array($list, ['allowlist', 'blocklist'], true)) {
            return ['success' => false, 'error' => 'Invalid IP list type; expected allowlist or blocklist.'];
        }
        if (!SignatureFeed::is_valid_ip_or_cidr($ip_or_cidr)) {
            return ['success' => false, 'error' => 'Invalid IPv4, IPv6, or CIDR notation.'];
        }

        $storage = self::resolve_storage_dir($storage_dir);
        self::ensure_dir($storage);

        $entry = [
            'ip'       => $ip_or_cidr,
            'note'     => trim($note),
            'added_at' => gmdate('c'),
        ];

        $rules = self::with_lock($storage, static function () use ($storage, $list, $ip_or_cidr, $entry): array {
            $current = self::read_ip_rules_unlocked($storage);
            $updated = [];
            foreach ($current[$list] as $item) {
                if (($item['ip'] ?? '') !== $ip_or_cidr) {
                    $updated[] = $item;
                }
            }
            $updated[]      = $entry;
            $current[$list] = $updated;
            self::atomic_write($storage . '/' . self::IP_RULES_FILE, FileIntegrity::simd_encode($current));
            return $current;
        });

        return [
            'success' => true,
            'entry'   => $entry,
            'rules'   => $rules,
        ];
    }

    /**
     * Remove an IP/CIDR entry from the allowlist or blocklist.
     */
    public static function remove_ip_rule(string $ip_or_cidr, string $list, ?string $storage_dir = null): bool {
        $ip_or_cidr = trim($ip_or_cidr);
        $list       = strtolower(trim($list));
        if ('' === $ip_or_cidr || !in_array($list, ['allowlist', 'blocklist'], true)) {
            return false;
        }

        $storage = self::resolve_storage_dir($storage_dir);
        if (!@is_file($storage . '/' . self::IP_RULES_FILE)) {
            return false;
        }

        return (bool) self::with_lock($storage, static function () use ($storage, $list, $ip_or_cidr): bool {
            $current = self::read_ip_rules_unlocked($storage);
            $before  = count($current[$list]);
            $kept    = [];
            foreach ($current[$list] as $item) {
                if (($item['ip'] ?? '') !== $ip_or_cidr) {
                    $kept[] = $item;
                }
            }
            if (count($kept) === $before) {
                return false;
            }
            $current[$list] = $kept;
            self::atomic_write($storage . '/' . self::IP_RULES_FILE, FileIntegrity::simd_encode($current));
            return true;
        });
    }

    /**
     * Check whether an IP matches any rule in an allowlist/blocklist array or flat IP list.
     *
     * @param array<int,mixed> $entries
     */
    public static function is_ip_in_list(string $ip, array $entries): bool {
        $ip = trim($ip);
        if ('' === $ip || false === @inet_pton($ip)) {
            return false;
        }

        foreach ($entries as $entry) {
            $rule = is_array($entry) ? (string) ($entry['ip'] ?? '') : (string) $entry;
            if ('' !== $rule && self::ip_matches_cidr($ip, $rule)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return active temporary auto-bans after pruning expired entries.
     *
     * @return array<string,array<string,mixed>>
     */
    public static function get_active_bans(?string $storage_dir = null): array {
        $storage = self::resolve_storage_dir($storage_dir);
        $path    = $storage . '/' . self::BANS_FILE;
        if (!@is_file($path)) {
            return [];
        }

        $raw     = self::read_json_file_unlocked($path);
        $now     = time();
        $active  = [];
        $expired = false;

        foreach ($raw as $key => $ban) {
            if (!is_array($ban)) {
                $expired = true;
                continue;
            }
            $ip    = trim((string) ($ban['ip'] ?? (is_string($key) ? $key : '')));
            $until = (int) ($ban['until'] ?? 0);
            if ('' === $ip || $until <= $now) {
                $expired = true;
                continue;
            }
            $ban['ip']    = $ip;
            $ban['until'] = $until;
            $active[$ip]  = $ban;
        }

        if ($expired) {
            self::with_lock($storage, static function () use ($storage, $path): void {
                $recheck = self::read_json_file_unlocked($path);
                $now_ts  = time();
                $pruned  = [];
                foreach ($recheck as $k => $b) {
                    if (!is_array($b)) {
                        continue;
                    }
                    $b_ip = trim((string) ($b['ip'] ?? (is_string($k) ? $k : '')));
                    $u    = (int) ($b['until'] ?? 0);
                    if ('' !== $b_ip && $u > $now_ts) {
                        $b['ip']       = $b_ip;
                        $b['until']    = $u;
                        $pruned[$b_ip] = $b;
                    }
                }
                self::atomic_write($path, FileIntegrity::simd_encode($pruned));
            });
        }

        return $active;
    }

    /**
     * Temporarily auto-ban an IP address for a number of minutes.
     *
     * @return array<string,mixed>
     */
    public static function ban_ip(string $ip, int $minutes, string $reason, ?string $storage_dir = null): array {
        $ip = trim($ip);
        if ('' === $ip || !SignatureFeed::is_valid_ip_or_cidr($ip)) {
            return ['success' => false, 'error' => 'Invalid IP address.'];
        }

        $minutes = max(1, $minutes);
        $storage = self::resolve_storage_dir($storage_dir);
        self::ensure_dir($storage);
        $now   = time();
        $until = $now + ($minutes * 60);

        $record = [
            'ip'         => $ip,
            'until'      => $until,
            'banned_at'  => gmdate('c', $now),
            'expires_at' => gmdate('c', $until),
            'minutes'    => $minutes,
            'reason'     => trim($reason),
        ];

        self::with_lock($storage, static function () use ($storage, $ip, $record, $now): void {
            $path = $storage . '/' . self::BANS_FILE;
            $raw  = self::read_json_file_unlocked($path);
            $bans = [];
            foreach ($raw as $k => $b) {
                if (!is_array($b)) {
                    continue;
                }
                $b_ip = trim((string) ($b['ip'] ?? (is_string($k) ? $k : '')));
                if ('' !== $b_ip && (int) ($b['until'] ?? 0) > $now) {
                    $b['ip']     = $b_ip;
                    $bans[$b_ip] = $b;
                }
            }
            $bans[$ip] = $record;
            self::atomic_write($path, FileIntegrity::simd_encode($bans));
        });

        return $record;
    }

    /**
     * Remove an active temporary ban for an IP address.
     */
    public static function unban_ip(string $ip, ?string $storage_dir = null): bool {
        $ip      = trim($ip);
        $storage = self::resolve_storage_dir($storage_dir);
        $path    = $storage . '/' . self::BANS_FILE;
        if ('' === $ip || !@is_file($path)) {
            return false;
        }

        return (bool) self::with_lock($storage, static function () use ($path, $ip): bool {
            $raw = self::read_json_file_unlocked($path);
            if (!isset($raw[$ip])) {
                return false;
            }
            unset($raw[$ip]);
            self::atomic_write($path, FileIntegrity::simd_encode($raw));
            return true;
        });
    }

    /**
     * Record a security strike for an IP/key and return the count within the time window.
     */
    public static function record_strike(string $ip, int $window_seconds = 900, ?string $storage_dir = null): int {
        $ip = trim($ip);
        if ('' === $ip) {
            return 0;
        }

        $window_seconds = max(1, $window_seconds);
        $storage        = self::resolve_storage_dir($storage_dir);
        self::ensure_dir($storage);
        $path = $storage . '/' . self::STRIKES_FILE;

        return (int) self::with_lock($storage, static function () use ($path, $ip, $window_seconds): int {
            $now     = time();
            $cutoff  = $now - $window_seconds;
            $raw     = self::read_json_file_unlocked($path);
            $cleaned = [];

            foreach ($raw as $key => $timestamps) {
                if (!is_array($timestamps)) {
                    continue;
                }
                $recent = [];
                foreach ($timestamps as $ts) {
                    $t = (int) $ts;
                    if ($t >= $cutoff) {
                        $recent[] = $t;
                    }
                }
                if (!empty($recent)) {
                    $cleaned[(string) $key] = $recent;
                }
            }

            if (!isset($cleaned[$ip])) {
                $cleaned[$ip] = [];
            }
            $cleaned[$ip][] = $now;
            $count          = count($cleaned[$ip]);

            self::atomic_write($path, FileIntegrity::simd_encode($cleaned));
            return $count;
        });
    }

    /**
     * Pure testable request evaluator.
     *
     * @param array<string,mixed>      $req
     * @param array<string,mixed>|null $settings
     * @return array<string,mixed>|null
     */
    public static function evaluate_request(array $req, ?string $storage_dir = null, ?array $settings = null): ?array {
        $ip         = trim((string) ($req['ip'] ?? ''));
        $uri        = (string) ($req['uri'] ?? '');
        $query      = (string) ($req['query'] ?? '');
        $body       = substr((string) ($req['body'] ?? ''), 0, 65536);
        $user_agent = (string) ($req['user_agent'] ?? '');

        $ip_rules = self::get_ip_rules($storage_dir);

        // Allowlist takes absolute precedence over blocklists, bans, and WAF patterns.
        if ('' !== $ip && self::is_ip_in_list($ip, $ip_rules['allowlist'])) {
            return null;
        }

        // Check manual blocklist, active temporary auto-bans, and threat-feed IP lists.
        if ('' !== $ip) {
            if (self::is_ip_in_list($ip, $ip_rules['blocklist'])) {
                return [
                    'category'        => 'ip_blocklist',
                    'rule'            => 'manual_blocklist',
                    'label'           => 'Manual IP blocklist match',
                    'severity'        => 'high',
                    'matched_snippet' => $ip,
                    'force_block'     => true,
                ];
            }

            $active_bans = self::get_active_bans($storage_dir);
            if (isset($active_bans[$ip]) || self::is_ip_in_list($ip, array_keys($active_bans))) {
                $ban_reason = isset($active_bans[$ip]['reason']) && '' !== $active_bans[$ip]['reason']
                    ? ': ' . (string) $active_bans[$ip]['reason']
                    : '';
                return [
                    'category'        => 'ip_blocklist',
                    'rule'            => 'auto_ban',
                    'label'           => 'Temporary auto-ban active' . $ban_reason,
                    'severity'        => 'high',
                    'matched_snippet' => $ip,
                    'force_block'     => true,
                ];
            }

            $feed_ips = SignatureFeed::get_feed_ips($storage_dir);
            if (!empty($feed_ips) && self::is_ip_in_list($ip, $feed_ips)) {
                return [
                    'category'        => 'ip_blocklist',
                    'rule'            => 'feed_ip_blocklist',
                    'label'           => 'Threat feed IP blocklist match',
                    'severity'        => 'high',
                    'matched_snippet' => $ip,
                    'force_block'     => true,
                ];
            }
        }

        // Prevent false positives when authenticated editors/admins save Gutenberg or Elementor content.
        if (!empty($req['is_authenticated_editor'])) {
            return null;
        }

        $block_xmlrpc = ($settings !== null && array_key_exists('block_xmlrpc', $settings))
            ? (bool) $settings['block_xmlrpc']
            : (function_exists('get_option') ? Settings::get_bool('block_xmlrpc', true) : true);

        if ($block_xmlrpc && str_contains(strtolower($uri), '/xmlrpc.php')) {
            return [
                'category'        => 'xmlrpc',
                'rule'            => 'xmlrpc_blocked',
                'label'           => 'XML-RPC blocked',
                'severity'        => 'high',
                'matched_snippet' => substr($uri, 0, 160),
                'force_block'     => false,
            ];
        }

        $decoded_uri   = rawurldecode($uri);
        $decoded_query = rawurldecode($query);
        $decoded_body  = rawurldecode($body);

        $targets = [
            'uri'   => trim($uri . ' ' . $decoded_uri),
            'query' => trim($query . ' ' . $decoded_query),
            'body'  => $body,
            'input' => trim($query . ' ' . $body . ' ' . $decoded_query . ' ' . $decoded_body),
            'ua'    => $user_agent,
        ];
        $targets['all'] = trim($targets['uri'] . ' ' . $targets['input'] . ' ' . $targets['ua']);

        $rules      = SignatureFeed::get_request_rules($storage_dir);
        $best_match = null;
        $best_rank  = 0;

        foreach ($rules as $rule) {
            if (!is_array($rule) || empty($rule['pattern'])) {
                continue;
            }
            $target_key = strtolower((string) ($rule['target'] ?? 'input'));
            $subject    = $targets[$target_key] ?? $targets['input'];
            if ('' === $subject) {
                continue;
            }

            $m = [];
            if (1 !== @preg_match((string) $rule['pattern'], $subject, $m)) {
                continue;
            }

            $severity = strtolower((string) ($rule['severity'] ?? 'medium'));
            $rank     = self::SEVERITY_RANK[$severity] ?? 1;
            if ($rank <= $best_rank) {
                continue;
            }

            $snippet    = trim(substr((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', (string) ($m[0] ?? '')), 0, 160));
            $best_rank  = $rank;
            $best_match = [
                'category'        => (string) ($rule['category'] ?? 'custom'),
                'rule'            => (string) ($rule['id'] ?? 'unknown'),
                'label'           => (string) ($rule['label'] ?? 'Suspicious request'),
                'severity'        => $severity,
                'matched_snippet' => $snippet,
                'force_block'     => false,
            ];

            if ($best_rank >= self::SEVERITY_RANK['critical']) {
                break;
            }
        }

        return $best_match;
    }

    /**
     * Inspect the live WordPress request at early init, log detections, apply auto-bans, and block when configured.
     */
    public static function inspect_current_request(): void {
        if (defined('WP_CLI') && WP_CLI) {
            return;
        }
        if (function_exists('is_admin') && is_admin()) {
            return;
        }
        if (function_exists('wp_doing_cron') && wp_doing_cron()) {
            return;
        }
        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
            return;
        }

        $mode = self::get_mode();
        if ('off' === $mode) {
            return;
        }

        $ip     = self::resolve_client_ip();
        $method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : 'GET');
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $uri = isset($_SERVER['REQUEST_URI']) ? self::unslash_str((string) $_SERVER['REQUEST_URI']) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $query = isset($_SERVER['QUERY_STRING']) ? self::unslash_str((string) $_SERVER['QUERY_STRING']) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? self::unslash_str((string) $_SERVER['HTTP_USER_AGENT']) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $referer = isset($_SERVER['HTTP_REFERER']) ? self::unslash_str((string) $_SERVER['HTTP_REFERER']) : '';

        $body = '';
        if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            $raw_body = @file_get_contents('php://input');
            if (is_string($raw_body) && '' !== $raw_body) {
                $body = substr($raw_body, 0, 65536);
            } elseif (!empty($_POST) && is_array($_POST)) {
                $body = substr(http_build_query($_POST), 0, 65536);
            }
        }

        $is_auth_editor = function_exists('is_user_logged_in')
            && is_user_logged_in()
            && function_exists('current_user_can')
            && current_user_can('edit_posts');

        $match = self::evaluate_request([
            'ip'                      => $ip,
            'method'                  => $method,
            'uri'                     => $uri,
            'query'                   => $query,
            'body'                    => $body,
            'user_agent'              => $user_agent,
            'referer'                 => $referer,
            'is_authenticated_editor' => $is_auth_editor,
        ]);

        if (null === $match) {
            return;
        }

        $block_xmlrpc = function_exists('get_option') ? Settings::get_bool('block_xmlrpc', true) : true;
        $should_block = 'block' === $mode
            || !empty($match['force_block'])
            || ('xmlrpc' === $match['category'] && $block_xmlrpc);
        $action = $should_block ? 'blocked' : 'logged';

        $auto_ban = function_exists('get_option') ? Settings::get_bool('auto_ban_enabled', true) : true;
        if (
            $auto_ban
            && '' !== $ip
            && 'ip_blocklist' !== $match['category']
            && in_array($match['severity'], ['critical', 'high'], true)
        ) {
            $strikes   = self::record_strike($ip);
            $threshold = function_exists('get_option') ? max(1, Settings::get_int('auto_ban_threshold', 5)) : 5;
            if ($strikes >= $threshold) {
                $minutes = function_exists('get_option') ? max(1, Settings::get_int('auto_ban_minutes', 60)) : 60;
                self::ban_ip($ip, $minutes, (string) $match['label']);
            }
        }

        $entry = self::record_event([
            'ip'              => $ip,
            'method'          => $method,
            'uri'             => $uri,
            'query'           => $query,
            'user_agent'      => $user_agent,
            'referer'         => $referer,
            'category'        => $match['category'],
            'rule'            => $match['rule'],
            'label'           => $match['label'],
            'severity'        => $match['severity'],
            'action'          => $action,
            'matched_snippet' => $match['matched_snippet'],
            'mode'            => $mode,
        ]);

        if (function_exists('do_action')) {
            do_action('gratis_security_malicious_request', $entry);
        }

        if ('blocked' === $action) {
            if (function_exists('do_action')) {
                do_action('gratis_security_blocked', (string) $match['label'], $ip);
            }
            self::send_forbidden_response();
        }
    }

    /**
     * Track probe-like 404 floods on template_redirect without penalizing normal broken links.
     */
    public static function track_404(): void {
        if (!function_exists('is_404') || !is_404()) {
            return;
        }
        $mode = self::get_mode();
        if ('off' === $mode) {
            return;
        }
        if (
            function_exists('is_user_logged_in')
            && is_user_logged_in()
            && function_exists('current_user_can')
            && current_user_can('edit_posts')
        ) {
            return;
        }

        $ip = self::resolve_client_ip();
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $uri = isset($_SERVER['REQUEST_URI']) ? self::unslash_str((string) $_SERVER['REQUEST_URI']) : '';
        if ('' === $ip || '' === $uri) {
            return;
        }

        $lower_uri = strtolower($uri);
        $is_probe  = false;
        foreach (['.php', '.env', '.sql', '.bak', '.zip', '.tar', 'wp-login', 'admin', 'config', '.git'] as $needle) {
            if (str_contains($lower_uri, $needle)) {
                $is_probe = true;
                break;
            }
        }
        if (!$is_probe) {
            return;
        }

        $count = self::record_strike($ip . '|404', 60);
        if ($count < 20) {
            return;
        }

        $auto_ban = function_exists('get_option') ? Settings::get_bool('auto_ban_enabled', true) : true;
        $action   = ('block' === $mode && $auto_ban) ? 'blocked' : 'logged';

        self::record_event([
            'ip'              => $ip,
            'method'          => strtoupper(isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : 'GET'),
            'uri'             => $uri,
            'category'        => '404_flood',
            'rule'            => '404_probe_flood',
            'label'           => 'Automated 404 probe flood',
            'severity'        => 'high',
            'action'          => $action,
            'matched_snippet' => "{$count} probe 404s in 60s",
            'mode'            => $mode,
        ]);

        if ('block' === $mode && $auto_ban) {
            $minutes = function_exists('get_option') ? max(1, Settings::get_int('auto_ban_minutes', 60)) : 60;
            self::ban_ip($ip, $minutes, 'Automated 404 probe flood');
        }
    }

    /**
     * Normalize and append a malicious request event to the JSONL log under LOCK_EX.
     *
     * @param array<string,mixed> $entry
     * @return array<string,mixed>
     */
    public static function record_event(array $entry, ?string $storage_dir = null): array {
        $storage = self::resolve_storage_dir($storage_dir);
        self::ensure_dir($storage);

        $time = trim((string) ($entry['time'] ?? ''));
        if ('' === $time) {
            $time = gmdate('c');
        }
        $ts = isset($entry['timestamp']) ? (int) $entry['timestamp'] : strtotime($time);
        if (false === $ts || $ts <= 0) {
            $ts = time();
        }

        $normalized = [
            'id'              => !empty($entry['id']) ? (string) $entry['id'] : ('req_' . bin2hex(random_bytes(6))),
            'time'            => $time,
            'timestamp'       => $ts,
            'ip'              => trim((string) ($entry['ip'] ?? '')),
            'method'          => strtoupper(trim((string) ($entry['method'] ?? 'GET'))),
            'uri'             => substr((string) ($entry['uri'] ?? ''), 0, 1024),
            'query'           => substr((string) ($entry['query'] ?? ''), 0, 1024),
            'user_agent'      => substr((string) ($entry['user_agent'] ?? ''), 0, 512),
            'referer'         => substr((string) ($entry['referer'] ?? ''), 0, 512),
            'category'        => strtolower(trim((string) ($entry['category'] ?? 'unknown'))),
            'rule'            => trim((string) ($entry['rule'] ?? '')),
            'label'           => trim((string) ($entry['label'] ?? 'Suspicious request')),
            'severity'        => strtolower(trim((string) ($entry['severity'] ?? 'medium'))),
            'action'          => strtolower(trim((string) ($entry['action'] ?? 'logged'))),
            'matched_snippet' => substr((string) ($entry['matched_snippet'] ?? ''), 0, 200),
            'mode'            => strtolower(trim((string) ($entry['mode'] ?? self::get_mode()))),
        ];

        $log_path = $storage . '/' . self::LOG_FILE;

        self::with_lock($storage, static function () use ($log_path, $normalized): void {
            $line = json_encode($normalized, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (!is_string($line)) {
                return;
            }
            @file_put_contents($log_path, $line . "\n", FILE_APPEND | LOCK_EX);

            // Trim only when line count exceeds MAX_LOG_ENTRIES so normal appends remain O(1).
            $lines = @file($log_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($lines) && count($lines) > self::MAX_LOG_ENTRIES) {
                $trimmed = array_slice($lines, -self::MAX_LOG_ENTRIES);
                self::atomic_write($log_path, implode("\n", $trimmed) . "\n");
            }
        });

        return $normalized;
    }

    /**
     * Query logged malicious requests with filtering, counts, top IPs, and pagination.
     *
     * @param array<string,mixed> $filters
     * @return array<string,mixed>
     */
    public static function query_requests(array $filters = [], ?string $storage_dir = null): array {
        $storage  = self::resolve_storage_dir($storage_dir);
        $log_path = $storage . '/' . self::LOG_FILE;

        if (!@is_file($log_path)) {
            self::migrate_legacy_blocks($storage, $log_path);
        }

        $entries     = self::read_log_entries($log_path);
        $active_bans = self::get_active_bans($storage);
        $ip_rules    = self::read_ip_rules_unlocked($storage);
        $now         = time();
        $day_cutoff  = $now - 86400;

        $counts = [
            'total'       => count($entries),
            'last_24h'    => 0,
            'blocked'     => 0,
            'logged'      => 0,
            'critical'    => 0,
            'high'        => 0,
            'medium'      => 0,
            'active_bans' => count($active_bans),
        ];

        $ip_hits_24h = [];
        foreach ($entries as $entry) {
            $ts     = (int) ($entry['timestamp'] ?? 0);
            $action = (string) ($entry['action'] ?? 'logged');
            $sev    = (string) ($entry['severity'] ?? 'medium');
            $ip     = (string) ($entry['ip'] ?? '');

            if ($ts >= $day_cutoff) {
                ++$counts['last_24h'];
                if ('' !== $ip) {
                    $ip_hits_24h[$ip] = ($ip_hits_24h[$ip] ?? 0) + 1;
                }
            }
            if ('blocked' === $action) {
                ++$counts['blocked'];
            } else {
                ++$counts['logged'];
            }
            if (isset($counts[$sev])) {
                ++$counts[$sev];
            }
        }

        arsort($ip_hits_24h);
        $top_ips = [];
        foreach (array_slice($ip_hits_24h, 0, 8, true) as $top_ip => $hit_count) {
            $is_blocked = isset($active_bans[$top_ip]) || self::is_ip_in_list($top_ip, $ip_rules['blocklist']);
            $top_ips[]  = [
                'ip'      => (string) $top_ip,
                'count'   => (int) $hit_count,
                'blocked' => $is_blocked,
            ];
        }

        $search   = self::normalize_filter((string) ($filters['search'] ?? ''));
        $category = self::normalize_filter((string) ($filters['category'] ?? ''));
        $severity = self::normalize_filter((string) ($filters['severity'] ?? ''));
        $action   = self::normalize_filter((string) ($filters['action'] ?? ''));
        $ip_filt  = trim((string) ($filters['ip'] ?? ''));
        if ('all' === strtolower($ip_filt)) {
            $ip_filt = '';
        }
        $since = strtolower(trim((string) ($filters['since'] ?? 'all')));

        $cutoff_ts = match ($since) {
            '15m' => $now - 900,
            '1h'  => $now - 3600,
            '24h' => $now - 86400,
            '7d'  => $now - 604800,
            default => 0,
        };

        $filtered = [];
        foreach (array_reverse($entries) as $entry) {
            if ($cutoff_ts > 0 && (int) ($entry['timestamp'] ?? 0) < $cutoff_ts) {
                continue;
            }
            if ('' !== $category && strtolower((string) ($entry['category'] ?? '')) !== $category) {
                continue;
            }
            if ('' !== $severity && strtolower((string) ($entry['severity'] ?? '')) !== $severity) {
                continue;
            }
            if ('' !== $action && strtolower((string) ($entry['action'] ?? '')) !== $action) {
                continue;
            }
            if ('' !== $ip_filt) {
                $entry_ip = (string) ($entry['ip'] ?? '');
                if ($entry_ip !== $ip_filt && !self::ip_matches_cidr($entry_ip, $ip_filt)) {
                    continue;
                }
            }
            if ('' !== $search) {
                $hay = strtolower(
                    ($entry['ip'] ?? '') . ' ' .
                    ($entry['uri'] ?? '') . ' ' .
                    ($entry['query'] ?? '') . ' ' .
                    ($entry['user_agent'] ?? '') . ' ' .
                    ($entry['category'] ?? '') . ' ' .
                    ($entry['rule'] ?? '') . ' ' .
                    ($entry['label'] ?? '') . ' ' .
                    ($entry['matched_snippet'] ?? '')
                );
                if (!str_contains($hay, $search)) {
                    continue;
                }
            }
            $filtered[] = $entry;
        }

        $total_filtered = count($filtered);
        $page           = isset($filters['page']) ? max(1, (int) $filters['page']) : 1;
        $per_page_raw   = $filters['per_page'] ?? ($filters['limit'] ?? 25);
        $per_page       = max(1, min(200, (int) $per_page_raw));
        $total_pages    = $total_filtered > 0 ? (int) ceil($total_filtered / $per_page) : 1;
        $offset         = ($page - 1) * $per_page;

        return [
            'requests'       => array_slice($filtered, $offset, $per_page),
            'counts'         => $counts,
            'top_ips'        => $top_ips,
            'total_filtered' => $total_filtered,
            'page'           => $page,
            'per_page'       => $per_page,
            'total_pages'    => $total_pages,
        ];
    }

    /**
     * Clear the malicious requests JSONL log.
     */
    public static function clear_requests(?string $storage_dir = null): void {
        $storage  = self::resolve_storage_dir($storage_dir);
        $log_path = $storage . '/' . self::LOG_FILE;
        if (!@is_dir($storage)) {
            return;
        }

        self::with_lock($storage, static function () use ($log_path): void {
            if (@file_exists($log_path)) {
                @unlink($log_path);
            }
        });
    }

    private static function normalize_filter(string $val): string {
        $norm = strtolower(trim($val));
        return 'all' === $norm ? '' : $norm;
    }

    private static function resolve_client_ip(): string {
        if (!isset($_SERVER['REMOTE_ADDR'])) {
            return '';
        }
        $raw = self::unslash_str((string) $_SERVER['REMOTE_ADDR']);
        $ip  = filter_var(trim($raw), FILTER_VALIDATE_IP);
        return false === $ip ? '' : (string) $ip;
    }

    private static function unslash_str(string $val): string {
        return function_exists('wp_unslash') ? (string) wp_unslash($val) : stripslashes($val);
    }

    private static function send_forbidden_response(): void {
        if (function_exists('status_header')) {
            status_header(403);
        } elseif (!headers_sent()) {
            http_response_code(403);
        }

        if (function_exists('nocache_headers')) {
            nocache_headers();
        }

        $msg   = function_exists('esc_html__') ? esc_html__('Request blocked by Gratis Security.', 'gratis-security') : 'Request blocked by Gratis Security.';
        $title = function_exists('esc_html__') ? esc_html__('Forbidden', 'gratis-security') : 'Forbidden';

        if (function_exists('wp_die')) {
            wp_die($msg, $title, ['response' => 403]);
        }
        exit(1);
    }

    private static function resolve_storage_dir(?string $storage_dir): string {
        if (null !== $storage_dir && '' !== $storage_dir) {
            return rtrim(str_replace('\\', '/', $storage_dir), '/');
        }
        if (function_exists('wp_upload_dir')) {
            return rtrim(str_replace('\\', '/', FileIntegrity::get_storage_dir()), '/');
        }
        if (defined('WP_CONTENT_DIR')) {
            return rtrim(str_replace('\\', '/', WP_CONTENT_DIR), '/') . '/' . FileIntegrity::STORAGE_DIR;
        }
        return rtrim(str_replace('\\', '/', sys_get_temp_dir()), '/') . '/' . FileIntegrity::STORAGE_DIR;
    }

    private static function ensure_dir(string $dir): void {
        if (!@is_dir($dir)) {
            if (function_exists('wp_mkdir_p')) {
                wp_mkdir_p($dir);
            } else {
                @mkdir($dir, 0755, true);
            }
        }
    }

    /**
     * @return array{allowlist:array<int,array<string,string>>,blocklist:array<int,array<string,string>>}
     */
    private static function read_ip_rules_unlocked(string $storage): array {
        $path = $storage . '/' . self::IP_RULES_FILE;
        $raw  = self::read_json_file_unlocked($path);

        $out = ['allowlist' => [], 'blocklist' => []];
        foreach (['allowlist', 'blocklist'] as $list) {
            if (!isset($raw[$list]) || !is_array($raw[$list])) {
                continue;
            }
            foreach ($raw[$list] as $item) {
                if (!is_array($item)) {
                    continue;
                }
                $ip = trim((string) ($item['ip'] ?? ''));
                if ('' === $ip || !SignatureFeed::is_valid_ip_or_cidr($ip)) {
                    continue;
                }
                $out[$list][] = [
                    'ip'       => $ip,
                    'note'     => (string) ($item['note'] ?? ''),
                    'added_at' => (string) ($item['added_at'] ?? ''),
                ];
            }
        }
        return $out;
    }

    /**
     * @return array<mixed>
     */
    private static function read_json_file_unlocked(string $path): array {
        if (!@is_file($path) || !@is_readable($path)) {
            return [];
        }
        $raw = (string) @file_get_contents($path);
        if ('' === $raw) {
            return [];
        }
        $decoded = FileIntegrity::simd_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private static function read_log_entries(string $log_path): array {
        if (!@is_file($log_path) || !@is_readable($log_path)) {
            return [];
        }
        $fp = @fopen($log_path, 'rb');
        if (!$fp) {
            return [];
        }
        $items = [];
        while (($line = fgets($fp)) !== false) {
            $line = trim($line);
            if ('' === $line) {
                continue;
            }
            $dec = FileIntegrity::simd_decode($line, true);
            if (is_array($dec)) {
                $items[] = $dec;
            }
        }
        fclose($fp);
        return $items;
    }

    /**
     * Migrate legacy waf-blocks.json (or legacy option) to malicious-requests.jsonl once.
     */
    private static function migrate_legacy_blocks(string $storage, string $log_path): void {
        $legacy_file = $storage . '/' . WAF::BLOCKS_FILE;
        $legacy_data = [];

        if (@is_file($legacy_file)) {
            $decoded = self::read_json_file_unlocked($legacy_file);
            if (!empty($decoded)) {
                $legacy_data = $decoded;
            }
        } elseif (function_exists('get_option')) {
            $opt = get_option('gratis_security_blocks', null);
            if (is_array($opt) && !empty($opt)) {
                $legacy_data = $opt;
            }
        }

        if (empty($legacy_data)) {
            return;
        }

        self::ensure_dir($storage);
        self::with_lock($storage, static function () use ($log_path, $legacy_data): void {
            if (@is_file($log_path)) {
                return;
            }
            $lines = [];
            foreach ($legacy_data as $item) {
                if (!is_array($item)) {
                    continue;
                }
                $time = (string) ($item['time'] ?? gmdate('c'));
                $ts   = strtotime($time);
                $row  = [
                    'id'              => 'req_' . bin2hex(random_bytes(6)),
                    'time'            => $time,
                    'timestamp'       => (false !== $ts && $ts > 0) ? $ts : time(),
                    'ip'              => trim((string) ($item['ip'] ?? '')),
                    'method'          => 'GET',
                    'uri'             => substr((string) ($item['uri'] ?? ''), 0, 1024),
                    'query'           => '',
                    'user_agent'      => '',
                    'referer'         => '',
                    'category'        => 'legacy_waf',
                    'rule'            => 'legacy_waf_block',
                    'label'           => trim((string) ($item['reason'] ?? 'Legacy WAF block')),
                    'severity'        => 'high',
                    'action'          => 'blocked',
                    'matched_snippet' => '',
                    'mode'            => 'block',
                ];
                $encoded = json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                if (is_string($encoded)) {
                    $lines[] = $encoded;
                }
            }
            if (!empty($lines)) {
                self::atomic_write($log_path, implode("\n", array_slice($lines, -self::MAX_LOG_ENTRIES)) . "\n");
            }
        });
    }

    /**
     * @template T
     * @param callable():T $fn
     * @return T
     */
    private static function with_lock(string $storage, callable $fn): mixed {
        $lock_fp = @fopen($storage . '/request-guard.lock', 'c+');
        if ($lock_fp) {
            @flock($lock_fp, LOCK_EX);
        }
        try {
            return $fn();
        } finally {
            if ($lock_fp) {
                @flock($lock_fp, LOCK_UN);
                @fclose($lock_fp);
            }
        }
    }

    private static function atomic_write(string $target, string $content): void {
        $dir = dirname($target);
        self::ensure_dir($dir);
        $tmp = @tempnam($dir, 'gs_');
        if (false === $tmp) {
            @file_put_contents($target, $content, LOCK_EX);
            return;
        }
        if (false !== @file_put_contents($tmp, $content)) {
            @chmod($tmp, 0640);
            if (!@rename($tmp, $target)) {
                @unlink($tmp);
                @file_put_contents($target, $content, LOCK_EX);
            }
        } else {
            @unlink($tmp);
        }
    }
}
