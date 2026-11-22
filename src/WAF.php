<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Web Application Firewall — backwards-compatible facade over RequestGuard.
 */
final class WAF {

    public const BLOCKS_FILE = 'waf-blocks.json';

    /**
     * Inspect the current request and log/block on a malicious match.
     */
    public static function check(): void {
        RequestGuard::inspect_current_request();
    }

    /**
     * Get the absolute path to the legacy blocks log file.
     */
    public static function get_blocks_file(): string {
        return FileIntegrity::get_storage_dir() . '/' . self::BLOCKS_FILE;
    }

    /**
     * Get recent blocked/logged requests (read from disk, zero MySQL queries).
     *
     * @param int $limit
     * @return array<int,array<string,mixed>>
     */
    public static function get_blocks(int $limit = 100): array {
        $per_page = $limit > 0 ? min(200, $limit) : 200;
        $res      = RequestGuard::query_requests(['per_page' => $per_page]);
        $rows     = [];

        // Legacy callers reverse the returned array expecting chronological order.
        foreach (array_reverse((array) ($res['requests'] ?? [])) as $req) {
            if (!is_array($req)) {
                continue;
            }
            $rows[] = array_merge($req, [
                'reason' => (string) ($req['label'] ?? $req['reason'] ?? ''),
                'ip'     => (string) ($req['ip'] ?? ''),
                'uri'    => (string) ($req['uri'] ?? ''),
                'time'   => (string) ($req['time'] ?? ''),
            ]);
        }

        return $rows;
    }

    /**
     * Clear the request/blocks logs completely.
     */
    public static function clear_blocks(): void {
        RequestGuard::clear_requests();
        $file = self::get_blocks_file();
        if (@file_exists($file)) {
            @unlink($file);
        }
        if (function_exists('delete_option')) {
            delete_option('gratis_security_blocks');
        }
    }
}
