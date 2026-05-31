<?php declare(strict_types=1);
namespace Gratis\Security;

/** Web Application Firewall — blocks common attack patterns. */
final class WAF
{
    public static function check(): void
    {
        if (is_admin() || (defined('WP_CLI') && WP_CLI)) return;

        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $query = $_SERVER['QUERY_STRING'] ?? '';
        $body = file_get_contents('php://input') ?: '';
        $input = $uri . $query . $body;

        // Block SQL injection attempts
        if (preg_match('/(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b.*\bwhere\b|\/\*.*\*\/|;\s*drop\s+table)/i', $input)) {
            self::block('SQL injection attempt');
        }

        // Block XSS attempts
        if (preg_match('/<script[^>]*>|javascript:|on\w+\s*=/i', $input)) {
            self::block('XSS attempt');
        }

        // Block path traversal
        if (preg_match('/\.\.[\/\\\\]/', $input)) {
            self::block('Path traversal');
        }

        // Block wp-config.php access attempts
        if (preg_match('/wp-config\.php/i', $uri)) {
            self::block('Config file access');
        }

        // Rate limit xmlrpc
        if (str_contains($uri, '/xmlrpc.php') && get_option('gratis_security_block_xmlrpc', true)) {
            self::block('XML-RPC blocked');
        }
    }

    private static function block(string $reason): void
    {
        $log = get_option('gratis_security_blocks', []);
        $log[] = ['reason' => $reason, 'ip' => $_SERVER['REMOTE_ADDR'] ?? '', 'uri' => $_SERVER['REQUEST_URI'] ?? '', 'time' => gmdate('c')];
        if (count($log) > 1000) $log = array_slice($log, -1000);
        update_option('gratis_security_blocks', $log, false);

        http_response_code(403);
        exit('Blocked by Gratis Security: ' . $reason);
    }
}
