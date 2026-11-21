<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Web Application Firewall — inspects incoming requests and blocks targeted
 * SQL-injection, XSS, sensitive file access, and path-traversal payloads before
 * WordPress dispatches.
 *
 * Uses disk-based storage with SIMDJSON acceleration for block logs to ensure
 * zero MySQL database overhead.
 */
final class WAF {

    public const BLOCKS_FILE = 'waf-blocks.json';

    /**
     * Inspect the current request and block on a malicious match.
     */
    public static function check(): void {
        if (defined('WP_CLI') && WP_CLI) {
            return;
        }
        if (is_admin()) {
            return;
        }
        if (function_exists('wp_doing_cron') && wp_doing_cron()) {
            return;
        }
        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
            return;
        }
        if (!Settings::get_bool('waf_enabled', false)) {
            return;
        }

        // Allow authenticated editors and administrators to navigate and save content without WAF blocks.
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('edit_posts')) {
            return;
        }

        // Raw, unsanitised request data is required so attack payloads remain
        // intact for pattern matching; values are never echoed unescaped.
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $uri   = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $query = isset($_SERVER['QUERY_STRING']) ? (string) wp_unslash($_SERVER['QUERY_STRING']) : '';
        $raw_uri = rawurldecode($uri);

        // 1. XML-RPC brute-force vector.
        if (Settings::get_bool('block_xmlrpc', true) && str_contains($uri, '/xmlrpc.php')) {
            self::block('XML-RPC blocked', $uri);
        }

        // 2. Direct access attempts to sensitive files (.env, wp-config.php, .git, .htaccess, web.config).
        if (preg_match('/(^|\/)(wp-config\.php|\.env|\.git|\.htaccess|web\.config)/i', $raw_uri)) {
            self::block('Config file access', $uri);
        }

        // 3. Path traversal in URI or query parameters.
        if (preg_match('/(?:\.\.[\/\\\\]|\b\.\.%2f|\b%2e%2e[\/\\\\])/i', $uri . ' ' . $query)) {
            self::block('Path traversal', $uri);
        }

        // Prepare query and body input for targeted SQLi and XSS checks.
        $check_input = $query;
        if ('POST' === ($_SERVER['REQUEST_METHOD'] ?? 'GET')) {
            $body = @file_get_contents('php://input');
            if (is_string($body) && '' !== $body) {
                $check_input .= ' ' . $body;
            }
        }

        if ('' === $check_input) {
            return;
        }

        // 4. Targeted SQL injection syntax (avoiding false positives on common words or CSS comments).
        $sqli_patterns = [
            '/\bunion\s+(?:all\s+)?select\b/i',
            '/;\s*(?:drop\s+table|alter\s+table|truncate\s+table)\b/i',
            '/\bbenchmark\s*\(\s*\d+\s*,/i',
            '/\bsleep\s*\(\s*\d+\s*\)/i',
            '/\bwaitfor\s+delay\s+[\'"]\d+/i',
            '/\b(?:extractvalue|updatexml)\s*\(/i',
            '/(?:\'|"|`)\s*(?:or|and)\s*[\'"]?1[\'"]?\s*=\s*[\'"]?1/i',
        ];
        foreach ($sqli_patterns as $pattern) {
            if (preg_match($pattern, $check_input)) {
                self::block('SQL injection attempt', $uri);
            }
        }

        // 5. Cross-site scripting (script tags, javascript URI protocol, data text/html, or tag event attributes).
        $xss_patterns = [
            '/<script\b[^>]*>/i',
            '/javascript\s*:[^\s]+/i',
            '/data\s*:\s*text\/html/i',
            '/<[^>]+[\s\/]\b(?:on\w+)\s*=\s*["\']?[^"\'>\s]*/i',
            '/vbscript\s*:/i',
        ];
        foreach ($xss_patterns as $pattern) {
            if (preg_match($pattern, $check_input)) {
                self::block('XSS attempt', $uri);
            }
        }
    }

    /**
     * Get the absolute path to the blocks log file.
     */
    public static function get_blocks_file(): string {
        return FileIntegrity::get_storage_dir() . '/' . self::BLOCKS_FILE;
    }

    /**
     * Get recent blocked requests (read from disk, zero MySQL queries).
     *
     * @param int $limit
     * @return array<int,array<string,mixed>>
     */
    public static function get_blocks(int $limit = 100): array {
        $file = self::get_blocks_file();
        $blocks = [];

        if (file_exists($file)) {
            $raw = (string) @file_get_contents($file);
            if ('' !== $raw) {
                $decoded = FileIntegrity::simd_decode($raw, true);
                if (is_array($decoded)) {
                    $blocks = $decoded;
                }
            }
        }

        // Clean up legacy database option if present to recover MySQL space.
        $legacy = get_option('gratis_security_blocks', null);
        if (is_array($legacy) && !empty($legacy)) {
            delete_option('gratis_security_blocks');
            if (empty($blocks)) {
                $blocks = $legacy;
                self::save_blocks($blocks);
            }
        }

        if ($limit > 0 && count($blocks) > $limit) {
            return array_slice($blocks, -$limit);
        }

        return $blocks;
    }

    /**
     * Save blocks to disk (zero MySQL).
     *
     * @param array<int,array<string,mixed>> $blocks
     */
    private static function save_blocks(array $blocks): void {
        $file = self::get_blocks_file();
        if (count($blocks) > 200) {
            $blocks = array_slice($blocks, -200);
        }
        $json = FileIntegrity::simd_encode($blocks);
        @file_put_contents($file, $json, LOCK_EX);
    }

    /**
     * Clear the blocks log completely.
     */
    public static function clear_blocks(): void {
        $file = self::get_blocks_file();
        if (file_exists($file)) {
            @unlink($file);
        }
        delete_option('gratis_security_blocks');
    }

    /**
     * Log the block to disk and terminate the request with a 403.
     */
    private static function block(string $reason, string $uri): void {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

        $blocks   = self::get_blocks(200);
        $blocks[] = [
            'reason' => $reason,
            'ip'     => $ip,
            'uri'    => esc_url_raw($uri),
            'time'   => gmdate('c'),
        ];
        self::save_blocks($blocks);

        /**
         * Fires when the WAF blocks a request.
         *
         * @param string $reason Human-readable block reason.
         * @param string $ip     Client IP address.
         */
        do_action('gratis_security_blocked', $reason, $ip);

        status_header(403);
        nocache_headers();
        wp_die(
            esc_html__('Request blocked by Gratis Security.', 'gratis-security'),
            esc_html__('Forbidden', 'gratis-security'),
            ['response' => 403]
        );
    }
}
