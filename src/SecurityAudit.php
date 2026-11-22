<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Pure-PHP WordPress and plugin security posture auditor.
 * Computes a weighted 0-100 hardening score and grade without database queries.
 */
final class SecurityAudit {

    /**
     * Run all security posture checks and return scored results.
     *
     * @return array<string,mixed>
     */
    public static function run(?string $project_root = null, ?string $storage_dir = null): array {
        $root    = (null !== $project_root && '' !== $project_root)
            ? rtrim(str_replace('\\', '/', $project_root), '/')
            : rtrim(str_replace('\\', '/', FileIntegrity::get_project_root()), '/');
        $storage = (null !== $storage_dir && '' !== $storage_dir)
            ? rtrim(str_replace('\\', '/', $storage_dir), '/')
            : rtrim(str_replace('\\', '/', FileIntegrity::get_storage_dir()), '/');

        $checks = [
            self::check_php_version(),
            self::check_file_editing(),
            self::check_debug_display(),
            self::check_storage_hardened($storage),
            self::check_headers_enabled(),
            self::check_xmlrpc_blocked(),
            self::check_login_protection(),
            self::check_request_monitoring(),
            self::check_fim_enabled(),
            self::check_signatures_fresh($storage),
            self::check_malware_scanned($storage),
            self::check_twofa_enabled(),
            self::check_wp_config_perms($root),
            self::check_default_admin_user(),
        ];

        $total_weight  = 0;
        $earned_weight = 0.0;
        $counts        = ['pass' => 0, 'warn' => 0, 'fail' => 0, 'total' => count($checks)];

        foreach ($checks as $chk) {
            $w = (int) ($chk['weight'] ?? 0);
            $s = (string) ($chk['status'] ?? 'fail');
            $total_weight += $w;

            if ('pass' === $s) {
                $earned_weight += (float) $w;
                ++$counts['pass'];
            } elseif ('warn' === $s) {
                $earned_weight += $w * 0.5;
                ++$counts['warn'];
            } else {
                ++$counts['fail'];
            }
        }

        $score = $total_weight > 0 ? (int) round(($earned_weight / $total_weight) * 100) : 0;
        $score = max(0, min(100, $score));

        $grade = match (true) {
            $score >= 90 => 'A',
            $score >= 75 => 'B',
            $score >= 60 => 'C',
            $score >= 45 => 'D',
            default      => 'F',
        };

        return [
            'score'      => $score,
            'grade'      => $grade,
            'counts'     => $counts,
            'checks'     => $checks,
            'checked_at' => gmdate('c'),
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_php_version(): array {
        $ver = PHP_VERSION;
        if (version_compare($ver, '8.2.0', '>=')) {
            $status = 'pass';
            $detail = "PHP {$ver} (supported)";
        } elseif (version_compare($ver, '8.1.0', '>=')) {
            $status = 'warn';
            $detail = "PHP {$ver} (security-only lifecycle; upgrade to 8.2+ recommended)";
        } else {
            $status = 'fail';
            $detail = "PHP {$ver} (EOL; upgrade to 8.2+ immediately)";
        }

        return self::entry(
            'php_version',
            'PHP Runtime Version',
            $status,
            10,
            $detail,
            false,
            'Upgrade PHP runtime to 8.2 or newer via your hosting control panel or system package manager.'
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_file_editing(): array {
        $mods = defined('DISALLOW_FILE_MODS') && (bool) DISALLOW_FILE_MODS;
        $edit = defined('DISALLOW_FILE_EDIT') && (bool) DISALLOW_FILE_EDIT;

        if ($mods || $edit) {
            return self::entry(
                'file_editing',
                'Theme/Plugin Editor Disabled',
                'pass',
                8,
                $mods ? 'DISALLOW_FILE_MODS is enabled' : 'DISALLOW_FILE_EDIT is enabled',
                false,
                ''
            );
        }

        return self::entry(
            'file_editing',
            'Theme/Plugin Editor Disabled',
            'warn',
            8,
            'Neither DISALLOW_FILE_EDIT nor DISALLOW_FILE_MODS is enabled',
            false,
            "Define define('DISALLOW_FILE_EDIT', true); in wp-config.php."
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_debug_display(): array {
        $wp_display   = defined('WP_DEBUG_DISPLAY') ? (bool) WP_DEBUG_DISPLAY : (defined('WP_DEBUG') && (bool) WP_DEBUG);
        $ini_raw      = strtolower(trim((string) ini_get('display_errors')));
        $ini_display  = !in_array($ini_raw, ['', '0', 'off', 'false', 'no'], true);

        if (!$wp_display && !$ini_display) {
            return self::entry(
                'debug_display',
                'Error Display Suppressed',
                'pass',
                8,
                'WP_DEBUG_DISPLAY and PHP display_errors are disabled',
                false,
                ''
            );
        }

        $status = $ini_display ? 'fail' : 'warn';
        return self::entry(
            'debug_display',
            'Error Display Suppressed',
            $status,
            8,
            sprintf('WP_DEBUG_DISPLAY=%s, display_errors=%s', $wp_display ? 'on' : 'off', $ini_display ? 'on' : 'off'),
            false,
            "Set define('WP_DEBUG_DISPLAY', false); and ini display_errors=Off in production."
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_storage_hardened(string $storage_dir): array {
        $exists   = @is_dir($storage_dir);
        $writable = $exists && @is_writable($storage_dir);
        $htaccess = $storage_dir . '/.htaccess';
        $has_ht   = @file_exists($htaccess) && str_contains((string) @file_get_contents($htaccess), 'denied');
        $has_idx  = @file_exists($storage_dir . '/index.php');

        if ($exists && $writable && $has_ht && $has_idx) {
            return self::entry(
                'storage_hardened',
                'Security Storage Directory Hardened',
                'pass',
                8,
                "Writable and protected with .htaccess deny + index.php ({$storage_dir})",
                false,
                ''
            );
        }

        return self::entry(
            'storage_hardened',
            'Security Storage Directory Hardened',
            'fail',
            8,
            sprintf('dir=%s writable=%s htaccess=%s index=%s', $exists ? 'yes' : 'no', $writable ? 'yes' : 'no', $has_ht ? 'yes' : 'no', $has_idx ? 'yes' : 'no'),
            false,
            'Ensure uploads/gratis-security is writable and contains .htaccess deny + index.php.'
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_headers_enabled(): array {
        $enabled = self::setting_bool('headers_enabled', true);
        return self::entry(
            'headers_enabled',
            'HTTP Security Headers',
            $enabled ? 'pass' : 'fail',
            8,
            $enabled ? 'Security response headers are active' : 'Security response headers are disabled',
            true,
            'Enable headers_enabled in Gratis Security settings.'
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_xmlrpc_blocked(): array {
        $blocked = self::setting_bool('block_xmlrpc', true);
        return self::entry(
            'xmlrpc_blocked',
            'XML-RPC Endpoint Protection',
            $blocked ? 'pass' : 'warn',
            6,
            $blocked ? 'XML-RPC endpoint is blocked' : 'XML-RPC endpoint is allowed',
            true,
            'Enable block_xmlrpc in Gratis Security settings.'
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_login_protection(): array {
        $enabled = self::setting_bool('login_protection', true);
        return self::entry(
            'login_protection',
            'Login Brute-Force Protection',
            $enabled ? 'pass' : 'fail',
            8,
            $enabled ? 'Login rate limiting and lockout active' : 'Login brute-force protection is disabled',
            true,
            'Enable login_protection in Gratis Security settings.'
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_request_monitoring(): array {
        $mode    = strtolower(self::setting_string('waf_mode', ''));
        $enabled = self::setting_bool('waf_enabled', false);

        if ('block' === $mode || 'monitor' === $mode || ('' === $mode && $enabled)) {
            $label_mode = '' !== $mode ? $mode : 'block';
            return self::entry(
                'request_monitoring',
                'WAF Request Inspection',
                'pass',
                10,
                "WAF inspection active (mode: {$label_mode})",
                true,
                ''
            );
        }

        return self::entry(
            'request_monitoring',
            'WAF Request Inspection',
            'warn',
            10,
            'WAF request monitoring/blocking is currently off',
            true,
            'Set waf_mode to monitor or block in Gratis Security settings.'
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_fim_enabled(): array {
        $enabled = self::setting_bool('integrity_enabled', true);
        return self::entry(
            'fim_enabled',
            'File Integrity Monitoring',
            $enabled ? 'pass' : 'warn',
            8,
            $enabled ? 'Scheduled File Integrity Monitoring is enabled' : 'File Integrity Monitoring is disabled',
            true,
            'Enable integrity_enabled in Gratis Security settings.'
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_signatures_fresh(string $storage_dir): array {
        $status       = SignatureFeed::get_status($storage_dir);
        $last_updated = (string) ($status['last_updated'] ?? '');
        $ts           = '' !== $last_updated ? strtotime($last_updated) : false;

        if (false !== $ts && $ts >= (time() - 7 * 86400)) {
            return self::entry(
                'signatures_fresh',
                'Threat Signature Feed Freshness',
                'pass',
                8,
                "Signatures updated at {$last_updated}",
                true,
                ''
            );
        }

        return self::entry(
            'signatures_fresh',
            'Threat Signature Feed Freshness',
            'warn',
            8,
            '' !== $last_updated ? "Signatures stale (last updated {$last_updated})" : 'Signature feed has not been synced to disk yet',
            true,
            'Run SignatureFeed::update() or trigger a signature update from the dashboard.'
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_malware_scanned(string $storage_dir): array {
        $report = MalwareScanner::get_last_report($storage_dir);
        if (!is_array($report)) {
            return self::entry(
                'malware_scanned',
                'Malware Scan Status',
                'warn',
                10,
                'No malware scan report recorded yet',
                true,
                'Run MalwareScanner::scan() to establish a clean baseline.'
            );
        }

        $counts   = (array) ($report['counts'] ?? []);
        $critical = (int) ($counts['critical'] ?? 0);
        $high     = (int) ($counts['high'] ?? 0);

        if ($critical > 0) {
            return self::entry(
                'malware_scanned',
                'Malware Scan Status',
                'fail',
                10,
                "{$critical} critical malware finding(s) in last scan ({$report['scanned_at']})",
                false,
                'Review and quarantine critical malware findings immediately.'
            );
        }

        if ($high > 0) {
            return self::entry(
                'malware_scanned',
                'Malware Scan Status',
                'warn',
                10,
                "{$high} high-severity finding(s) in last scan ({$report['scanned_at']})",
                false,
                'Inspect high-severity findings and quarantine or whitelist verified files.'
            );
        }

        return self::entry(
            'malware_scanned',
            'Malware Scan Status',
            'pass',
            10,
            sprintf('Clean scan (%d files checked at %s)', (int) ($report['scanned'] ?? 0), (string) ($report['scanned_at'] ?? '')),
            false,
            ''
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_twofa_enabled(): array {
        $enabled = self::setting_bool('twofa_enabled', false);
        return self::entry(
            'twofa_enabled',
            'Two-Factor Authentication (TOTP)',
            $enabled ? 'pass' : 'warn',
            6,
            $enabled ? 'TOTP 2FA enforcement is enabled' : 'TOTP 2FA is not enforced globally',
            false,
            'Enroll admin TOTP keys first, then enable twofa_enabled in settings.'
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_wp_config_perms(string $project_root): array {
        $candidates = [
            $project_root . '/wp-config.php',
            dirname($project_root) . '/wp-config.php',
        ];
        if (defined('ABSPATH')) {
            $ab           = rtrim(str_replace('\\', '/', ABSPATH), '/');
            $candidates[] = $ab . '/wp-config.php';
            $candidates[] = dirname($ab) . '/wp-config.php';
        }

        $found = '';
        foreach (array_unique($candidates) as $cand) {
            if (@file_exists($cand) && @is_file($cand)) {
                $found = $cand;
                break;
            }
        }

        if ('' === $found) {
            return self::entry(
                'wp_config_perms',
                'wp-config.php File Permissions',
                'pass',
                6,
                'wp-config.php not exposed inside scanned web root',
                false,
                ''
            );
        }

        $perms = @fileperms($found);
        if (false === $perms) {
            return self::entry(
                'wp_config_perms',
                'wp-config.php File Permissions',
                'warn',
                6,
                "Unable to inspect permissions on {$found}",
                false,
                'Ensure wp-config.php uses 0640 or 0600 permissions.'
            );
        }

        $mode = $perms & 0777;
        $oct  = sprintf('%04o', $mode);
        if (0 !== ($mode & 0002)) {
            return self::entry(
                'wp_config_perms',
                'wp-config.php File Permissions',
                'fail',
                6,
                "wp-config.php is world-writable ({$oct})",
                false,
                'Run chmod 640 wp-config.php immediately.'
            );
        }

        if (0 !== ($mode & 0004)) {
            return self::entry(
                'wp_config_perms',
                'wp-config.php File Permissions',
                'warn',
                6,
                "wp-config.php is world-readable ({$oct})",
                false,
                'Tighten wp-config.php permissions to 0640 or 0600.'
            );
        }

        return self::entry(
            'wp_config_perms',
            'wp-config.php File Permissions',
            'pass',
            6,
            "wp-config.php permissions restricted ({$oct})",
            false,
            ''
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function check_default_admin_user(): array {
        if (!function_exists('get_user_by')) {
            return self::entry(
                'default_admin_user',
                'Default Admin Username Absent',
                'pass',
                6,
                'Skipped (WordPress user API unavailable in CLI)',
                false,
                ''
            );
        }

        foreach (['admin', 'root'] as $name) {
            $user = get_user_by('login', $name);
            if ($user instanceof \WP_User && in_array('administrator', (array) $user->roles, true)) {
                return self::entry(
                    'default_admin_user',
                    'Default Admin Username Absent',
                    'fail',
                    6,
                    "Administrator account uses predictable login '{$name}'",
                    false,
                    "Create a uniquely named administrator account and remove '{$name}'."
                );
            }
        }

        return self::entry(
            'default_admin_user',
            'Default Admin Username Absent',
            'pass',
            6,
            'No administrator accounts named admin or root',
            false,
            ''
        );
    }

    private static function setting_bool(string $key, bool $fallback): bool {
        if (function_exists('get_option')) {
            return Settings::get_bool($key, $fallback);
        }
        return $fallback;
    }

    private static function setting_string(string $key, string $fallback): string {
        if (function_exists('get_option')) {
            return Settings::get_string($key, $fallback);
        }
        return $fallback;
    }

    /**
     * @return array<string,mixed>
     */
    private static function entry(
        string $id,
        string $label,
        string $status,
        int $weight,
        string $detail,
        bool $can_auto_fix,
        string $fix_hint
    ): array {
        return [
            'id'           => $id,
            'label'        => $label,
            'status'       => $status,
            'weight'       => $weight,
            'detail'       => $detail,
            'can_auto_fix' => $can_auto_fix,
            'fix_hint'     => $fix_hint,
        ];
    }
}
