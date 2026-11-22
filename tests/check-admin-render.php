<?php declare(strict_types=1);

PHP_SAPI === 'cli' || exit(1);

error_reporting(E_ALL);

set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    throw new \ErrorException($message, 0, $severity, $file, $line);
});

$tmp_root    = sys_get_temp_dir() . '/gratis_sec_admin_' . bin2hex(random_bytes(4));
$tmp_web     = $tmp_root . '/web';
$tmp_wp      = $tmp_web . '/wp';
$tmp_uploads = $tmp_web . '/app/uploads';
$tmp_storage = $tmp_uploads . '/gratis-security';

@mkdir($tmp_wp . '/wp-includes', 0755, true);
@mkdir($tmp_uploads, 0755, true);
@mkdir($tmp_web . '/app/plugins/demo-plugin', 0755, true);
@mkdir($tmp_storage, 0755, true);

define('ABSPATH', $tmp_wp . '/');
define('WP_CONTENT_DIR', $tmp_web . '/app');

$GLOBALS['gratis_test_options'] = [];
$GLOBALS['gratis_test_crons']   = [];

if (!function_exists('__')) {
    function __(string $text, string $domain = 'default'): string {
        return $text;
    }
}
if (!function_exists('esc_html')) {
    function esc_html(string $text): string {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}
if (!function_exists('esc_html__')) {
    function esc_html__(string $text, string $domain = 'default'): string {
        return esc_html($text);
    }
}
if (!function_exists('esc_attr')) {
    function esc_attr(string $text): string {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}
if (!function_exists('esc_attr__')) {
    function esc_attr__(string $text, string $domain = 'default'): string {
        return esc_attr($text);
    }
}
if (!function_exists('esc_url')) {
    function esc_url(string $url): string {
        return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
    }
}
if (!function_exists('esc_url_raw')) {
    function esc_url_raw(string $url, ?array $protocols = null): string {
        $url = trim($url);
        if ('' === $url) {
            return '';
        }
        if (is_array($protocols) && !empty($protocols)) {
            $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
            if ('' !== $scheme && !in_array($scheme, $protocols, true)) {
                return '';
            }
        }
        return filter_var($url, FILTER_SANITIZE_URL) ?: '';
    }
}
if (!function_exists('esc_js')) {
    function esc_js(string $text): string {
        return str_replace(["\\", "'", "\"", "\n", "\r"], ["\\\\", "\\'", "\\\"", "\\n", "\\r"], $text);
    }
}
if (!function_exists('wp_create_nonce')) {
    function wp_create_nonce(string|int $action = -1): string {
        return 'test_nonce_' . md5((string) $action);
    }
}
if (!function_exists('admin_url')) {
    function admin_url(string $path = '', string $scheme = 'admin'): string {
        return 'https://example.test/wp-admin/' . ltrim($path, '/');
    }
}
if (!function_exists('home_url')) {
    function home_url(string $path = '', ?string $scheme = null): string {
        return 'https://example.test/' . ltrim($path, '/');
    }
}
if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir(): array {
        return ['basedir' => WP_CONTENT_DIR . '/uploads'];
    }
}
if (!function_exists('wp_mkdir_p')) {
    function wp_mkdir_p(string $target): bool {
        return is_dir($target) || @mkdir($target, 0755, true);
    }
}
if (!function_exists('wp_next_scheduled')) {
    function wp_next_scheduled(string $hook): int|false {
        return $GLOBALS['gratis_test_crons'][$hook] ?? false;
    }
}
if (!function_exists('current_user_can')) {
    function current_user_can(string $capability, mixed ...$args): bool {
        return true;
    }
}
if (!function_exists('get_option')) {
    function get_option(string $option, mixed $default = false): mixed {
        return $GLOBALS['gratis_test_options'][$option] ?? $default;
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
if (!function_exists('get_date_from_gmt')) {
    function get_date_from_gmt(string $string, string $format = 'Y-m-d H:i:s'): string {
        $ts = strtotime($string . ' UTC');
        return false !== $ts ? gmdate($format, $ts) : $string;
    }
}
if (!function_exists('size_format')) {
    function size_format(int|float|string $bytes, int $decimals = 0): string|false {
        $bytes = (float) $bytes;
        if ($bytes >= 1048576) {
            return number_format($bytes / 1048576, $decimals) . ' MB';
        }
        if ($bytes >= 1024) {
            return number_format($bytes / 1024, $decimals) . ' KB';
        }
        return number_format($bytes, $decimals) . ' B';
    }
}
if (!function_exists('wp_unslash')) {
    function wp_unslash(string|array $value): string|array {
        return is_array($value) ? array_map('stripslashes', $value) : stripslashes($value);
    }
}
if (!function_exists('sanitize_key')) {
    function sanitize_key(string $key): string {
        return (string) preg_replace('/[^a-z0-9_\-]/', '', strtolower($key));
    }
}
if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field(string $str): string {
        return trim(strip_tags($str));
    }
}
if (!function_exists('absint')) {
    function absint(mixed $maybeint): int {
        return abs((int) $maybeint);
    }
}
if (!function_exists('checked')) {
    function checked(mixed $checked, mixed $current = true, bool $display = true): string {
        $res = ((string) $checked === (string) $current) ? " checked='checked'" : '';
        if ($display) {
            echo $res;
        }
        return $res;
    }
}
if (!function_exists('selected')) {
    function selected(mixed $selected, mixed $current = true, bool $display = true): string {
        $res = ((string) $selected === (string) $current) ? " selected='selected'" : '';
        if ($display) {
            echo $res;
        }
        return $res;
    }
}
if (!function_exists('settings_fields')) {
    function settings_fields(string $option_group): void {
        echo '<input type="hidden" name="option_page" value="' . esc_attr($option_group) . '">';
    }
}
if (!function_exists('submit_button')) {
    function submit_button(?string $text = null): void {
        echo '<p class="submit"><input type="submit" name="submit" id="submit" class="button button-primary" value="' . esc_attr($text ?? 'Save Changes') . '"></p>';
    }
}
if (!function_exists('settings_errors')) {
    function settings_errors(string $setting = ''): void {
    }
}
if (!function_exists('wp_nonce_field')) {
    function wp_nonce_field(string|int $action = -1, string $name = '_wpnonce', bool $referer = true, bool $display = true): string {
        $field = '<input type="hidden" id="' . esc_attr($name) . '" name="' . esc_attr($name) . '" value="' . esc_attr(wp_create_nonce($action)) . '">';
        if ($display) {
            echo $field;
        }
        return $field;
    }
}
if (!function_exists('get_bloginfo')) {
    function get_bloginfo(string $show = '', string $filter = 'raw'): string {
        return 'version' === $show ? '6.7.1' : 'Gratis Test';
    }
}
if (!function_exists('is_ssl')) {
    function is_ssl(): bool {
        return true;
    }
}
if (!function_exists('is_admin')) {
    function is_admin(): bool {
        return true;
    }
}
if (!function_exists('apply_filters')) {
    function apply_filters(string $hook_name, mixed $value, mixed ...$args): mixed {
        return $value;
    }
}
if (!function_exists('do_action')) {
    function do_action(string $hook_name, mixed ...$args): void {
    }
}
if (!function_exists('wp_json_encode')) {
    function wp_json_encode(mixed $data, int $flags = 0, int $depth = 512): string|false {
        return json_encode($data, $flags, $depth);
    }
}
if (!function_exists('wp_die')) {
    function wp_die(string $message = ''): never {
        throw new \RuntimeException('wp_die: ' . $message);
    }
}

require_once dirname(__DIR__) . '/autoload.php';

use Gratis\Security\EventMonitor;
use Gratis\Security\RequestGuard;
use Gratis\Security\Settings;

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
            @unlink($path);
        }
    }
    @rmdir($dir);
}

try {
    // Seed 30 synthetic FIM detections so pagination (> 25/page) renders on server tab.
    $det_lines = [];
    $now       = time();
    for ($i = 1; $i <= 30; $i++) {
        $det_lines[] = json_encode([
            'id'          => sprintf('det_%03d', $i),
            'event_time'  => gmdate('Y-m-d H:i:s', $now - ($i * 60)),
            'detected_at' => gmdate('c', $now - ($i * 60)),
            'severity'    => ($i % 3 === 0) ? 'critical' : (($i % 2 === 0) ? 'high' : 'medium'),
            'status'      => 'open',
            'rule'        => 'php_write_untrusted',
            'title'       => "Synthetic FIM event #{$i}",
            'details'     => "Modified php file #{$i}",
            'path'        => "web/app/uploads/suspect-{$i}.php",
            'component'   => 'uploads',
            'event'       => 'CLOSE_WRITE',
        ], JSON_UNESCAPED_SLASHES);
    }
    file_put_contents($tmp_storage . '/' . EventMonitor::DETECTIONS_FILE, implode("\n", $det_lines) . "\n");

    // Seed 30 synthetic malicious requests so pagination (> 25/page) renders on requests/blocks tabs.
    $req_lines = [];
    for ($i = 1; $i <= 30; $i++) {
        $ts          = $now - ($i * 30);
        $req_lines[] = json_encode([
            'time'            => gmdate('Y-m-d H:i:s', $ts),
            'timestamp'       => $ts,
            'ip'              => '198.51.100.' . $i,
            'method'          => 'GET',
            'uri'             => '/?s=' . $i,
            'query'           => 'id=1 UNION SELECT 1,2',
            'user_agent'      => 'SyntheticTest/1.0',
            'category'        => 'sqli',
            'severity'        => 'high',
            'action'          => ($i % 2 === 0) ? 'blocked' : 'logged',
            'rule'            => 'sqli_union_select',
            'label'           => 'SQL Injection UNION SELECT',
            'matched_snippet' => 'UNION SELECT 1,2',
        ], JSON_UNESCAPED_SLASHES);
    }
    file_put_contents($tmp_storage . '/' . RequestGuard::LOG_FILE, implode("\n", $req_lines) . "\n");

    // Verify all 8 tabs render cleanly with zero warnings/notices and zero innerHTML.
    $tab_expectations = [
        'wizard'   => ['gs-wiz-run-btn', 'gs-wiz-waf-mode', 'gs-code-head'],
        'fim'      => ['gratis-scan-btn', 'gratis-baseline-btn'],
        'malware'  => ['gs-malware-quick-btn', 'gs-malware-deep-btn', 'gs-quarantine-body'],
        'requests' => ['gs-requests-body', 'gs-requests-pager', 'Puslapis 1 iš 2 (viso 30)'],
        'blocks'   => ['gs-requests-body', 'gs-requests-pager', 'Puslapis 1 iš 2 (viso 30)'],
        'feeds'    => ['gs-feeds-update-btn', 'signature_feed_url'],
        'server'   => ['gratis-detections-body', 'gratis-det-pager', 'gratis-logs-body', 'gs-code-head', 'Puslapis 1 iš 2 (viso 30)'],
        'general'  => ['waf_mode', 'auto_ban_enabled'],
    ];

    foreach ($tab_expectations as $tab_name => $markers) {
        $_GET['tab'] = $tab_name;
        ob_start();
        Settings::render_page();
        $html = (string) ob_get_clean();

        assert('' !== trim($html), "Tab '{$tab_name}' rendered empty HTML.");
        assert(!str_contains($html, 'innerHTML'), "Tab '{$tab_name}' contains forbidden innerHTML.");

        foreach ($markers as $marker) {
            assert(str_contains($html, $marker), "Tab '{$tab_name}' missing expected marker '{$marker}'.");
        }
    }

    // Confirm pagination next buttons are enabled (not disabled) when 30 rows (> 25 per page) are seeded.
    $_GET['tab'] = 'requests';
    ob_start();
    Settings::render_page();
    $req_html = (string) ob_get_clean();
    assert(str_contains($req_html, '<button type="button" id="gs-req-next" class="button button-small">'), 'Requests pagination next button should be enabled for 30 entries.');

    $_GET['tab'] = 'server';
    ob_start();
    Settings::render_page();
    $srv_html = (string) ob_get_clean();
    assert(str_contains($srv_html, '<button type="button" id="gratis-det-next" class="button button-small">'), 'Detections pagination next button should be enabled for 30 entries.');

    // Test Settings::sanitize() preserves feed and wizard keys when saving General settings.
    $GLOBALS['gratis_test_options'][Settings::OPTION] = [
        'signature_feed_url'   => 'https://feeds.example/sigs.json',
        'signature_feed_token' => 'secret123',
        'ip_feed_url'          => 'https://feeds.example/ips.txt',
        'wizard_completed_at'  => '2026-11-23T00:00:00+00:00',
    ];

    $sanitized = Settings::sanitize([
        'waf_mode'          => 'block',
        'block_xmlrpc'      => '1',
        'headers_enabled'   => '1',
        'login_protection'  => '1',
        'integrity_enabled' => '1',
    ]);

    assert($sanitized['waf_mode'] === 'block', 'waf_mode should update to block.');
    assert($sanitized['waf_enabled'] === 1, 'waf_enabled should sync to 1 for block mode.');
    assert($sanitized['signature_feed_url'] === 'https://feeds.example/sigs.json', 'signature_feed_url must be preserved.');
    assert($sanitized['signature_feed_token'] === 'secret123', 'signature_feed_token must be preserved.');
    assert($sanitized['ip_feed_url'] === 'https://feeds.example/ips.txt', 'ip_feed_url must be preserved.');
    assert($sanitized['wizard_completed_at'] === '2026-11-23T00:00:00+00:00', 'wizard_completed_at must be preserved.');

    // Also verify explicit _general_form submission preserves feed + wizard keys while toggling unchecked general checkboxes to 0.
    $sanitized_general = Settings::sanitize([
        '_general_form'     => '1',
        'waf_mode'          => 'monitor',
        'block_xmlrpc'      => '1',
        'headers_enabled'   => '1',
        'login_protection'  => '1',
        'integrity_enabled' => '1',
    ]);

    assert($sanitized_general['waf_mode'] === 'monitor');
    assert($sanitized_general['waf_enabled'] === 0);
    assert($sanitized_general['auto_ban_enabled'] === 0);
    assert($sanitized_general['signature_feed_url'] === 'https://feeds.example/sigs.json');
    assert($sanitized_general['signature_feed_token'] === 'secret123');
    assert($sanitized_general['ip_feed_url'] === 'https://feeds.example/ips.txt');
    assert($sanitized_general['wizard_completed_at'] === '2026-11-23T00:00:00+00:00');

    echo "ALL CHECKS PASSED (admin render 8 tabs + pagination + Settings::sanitize)\n";
} finally {
    restore_error_handler();
    rm_rf($tmp_root);
}
