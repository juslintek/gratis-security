<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Web Application Firewall — inspects the incoming request and blocks common
 * SQL-injection, XSS, and path-traversal payloads before WordPress dispatches.
 */
final class WAF {

    /**
     * Inspect the current request and block on a malicious match.
     */
    public static function check(): void {
        if (is_admin() || (defined('WP_CLI') && WP_CLI)) {
            return;
        }
        if (!Settings::get_bool('waf_enabled', true)) {
            return;
        }

        // Raw, unsanitised request data is required so attack payloads remain
        // intact for pattern matching; values are never echoed unescaped.
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $uri   = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $query = isset($_SERVER['QUERY_STRING']) ? (string) wp_unslash($_SERVER['QUERY_STRING']) : '';
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading the raw request body, not a remote URL.
        $body  = file_get_contents('php://input');
        $body  = is_string($body) ? $body : '';
        $input = $uri . ' ' . $query . ' ' . $body;

        // XML-RPC brute-force vector.
        if (str_contains($uri, '/xmlrpc.php') && Settings::get_bool('block_xmlrpc', true)) {
            self::block('XML-RPC blocked', $uri);
        }

        // Direct wp-config.php access attempts.
        if (preg_match('/wp-config\.php/i', $uri)) {
            self::block('Config file access', $uri);
        }

        // SQL injection.
        if (preg_match('/(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b.*\bwhere\b|\/\*.*\*\/|;\s*drop\s+table)/i', $input)) {
            self::block('SQL injection attempt', $uri);
        }

        // Cross-site scripting.
        if (preg_match('/<script[^>]*>|javascript:|on\w+\s*=/i', $input)) {
            self::block('XSS attempt', $uri);
        }

        // Path traversal.
        if (preg_match('/\.\.[\/\\\\]/', $input)) {
            self::block('Path traversal', $uri);
        }
    }

    /**
     * Log the block and terminate the request with a 403.
     */
    private static function block(string $reason, string $uri): void {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

        $log = get_option('gratis_security_blocks', []);
        if (!is_array($log)) {
            $log = [];
        }
        $log[] = [
            'reason' => $reason,
            'ip'     => $ip,
            'uri'    => esc_url_raw($uri),
            'time'   => gmdate('c'),
        ];
        if (count($log) > 1000) {
            $log = array_slice($log, -1000);
        }
        update_option('gratis_security_blocks', $log, false);

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
