<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * PHP-first auto-configurator and unified security posture wizard.
 * Provisions everything WordPress/PHP can configure with zero SSH access,
 * while surfacing optional OS-level enhancements cleanly.
 */
final class SetupWizard {

    /**
     * Detect PHP extensions, storage permissions, WP-Cron state, and optional scanner binaries.
     *
     * @return array<string,mixed>
     */
    public static function detect_php_capabilities(?string $storage_dir = null): array {
        $ext_names  = ['simdjson', 'inotify', 'openssl', 'curl', 'posix', 'fileinfo', 'zlib', 'json'];
        $extensions = [];
        foreach ($ext_names as $ext) {
            $extensions[$ext] = extension_loaded($ext);
        }

        $storage          = self::resolve_storage_dir($storage_dir);
        $storage_writable = '' !== $storage && @is_dir($storage) && @is_writable($storage); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Low-level local filesystem/OS security operation.

        $disable_wp_cron = defined('DISABLE_WP_CRON') && (bool) DISABLE_WP_CRON;
        $wp_cron_enabled = !$disable_wp_cron;

        return [
            'extensions'       => $extensions,
            'storage_dir'      => $storage,
            'storage_writable' => $storage_writable,
            'wp_cron_enabled'  => $wp_cron_enabled,
            'disable_wp_cron'  => $disable_wp_cron,
            'wp_cron_note'     => $disable_wp_cron
                ? 'DISABLE_WP_CRON is true; ensure system cron executes `wp cron event run --due-now` regularly to drive WP-Cron hooks.'
                : 'Native WP-Cron is active and will dispatch scheduled security hooks.',
            'clamav'           => MalwareScanner::detect_clamav(),
            'can_shell'        => FileIntegrity::is_shell_available(),
        ];
    }

    /**
     * Gather the complete wizard diagnostic state across PHP capabilities, audit, feeds, malware, and server layers.
     *
     * @return array<string,mixed>
     */
    public static function diagnose(string $service_user_mode = 'php', ?string $project_root = null, ?string $storage_dir = null): array {
        $storage = self::resolve_storage_dir($storage_dir);
        $root    = (null !== $project_root && '' !== $project_root)
            ? rtrim(str_replace('\\', '/', $project_root), '/')
            : rtrim(str_replace('\\', '/', FileIntegrity::get_project_root()), '/');

        $wizard_completed_at = function_exists('get_option') ? Settings::get_string('wizard_completed_at', '') : '';
        $php_capabilities    = self::detect_php_capabilities($storage);
        $audit               = SecurityAudit::run($root, $storage);
        $signatures          = SignatureFeed::get_status($storage);
        $malware             = MalwareScanner::get_last_report($storage);
        $server              = ServerInspector::inspect($service_user_mode);
        $detections_counts   = EventMonitor::query_detections(['per_page' => 1], $storage)['counts'];
        $requests_counts     = RequestGuard::query_requests(['per_page' => 1], $storage)['counts'];

        $auto_actions_summary = [
            'Harden disk storage directory (.htaccess, index.php) and initialize fim-events.jsonl.',
            'Enable safe PHP security defaults (security headers, XML-RPC block, login protection, FIM, RequestGuard monitor/block mode, auto-ban, signature & malware schedules).',
            'Sync built-in and remote malware/WAF threat signatures to disk.',
            'Schedule recurring WP-Cron jobs for FIM, log trailing, malware scans, and signature updates.',
            'Purge stale false-positive FIM detections already verified clean by SOURCE-MANIFEST.sha256.',
            'Run initial File Integrity and Malware baseline scans.',
        ];

        $recs = (array) ($server['recommendations'] ?? []);
        $optional_os_upgrades = self::build_optional_os_upgrades($recs);

        return [
            'wizard_completed_at'  => $wizard_completed_at,
            'php_capabilities'     => $php_capabilities,
            'audit'                => $audit,
            'signatures'           => $signatures,
            'malware'              => $malware,
            'server'               => $server,
            'detections_counts'    => $detections_counts,
            'requests_counts'      => $requests_counts,
            'auto_actions_summary' => $auto_actions_summary,
            'optional_os_upgrades' => $optional_os_upgrades,
        ];
    }

    /**
     * Execute the 1-click PHP-only security auto-configuration sequence (idempotent, zero SSH).
     *
     * @param array<string,mixed> $options
     * @return array<string,mixed>
     */
    public static function run_auto_configure(array $options = [], ?string $project_root = null, ?string $storage_dir = null): array {
        $storage = self::resolve_storage_dir($storage_dir);
        $root    = (null !== $project_root && '' !== $project_root)
            ? rtrim(str_replace('\\', '/', $project_root), '/')
            : rtrim(str_replace('\\', '/', FileIntegrity::get_project_root()), '/');

        $steps        = [];
        $completed_at = gmdate('c');

        // Step 1: Ensure hardened storage directory and base events log exist.
        self::ensure_hardened_storage($storage);
        $events_file = $storage . '/' . EventMonitor::EVENTS_FILE;
        if (!@file_exists($events_file)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            @touch($events_file); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_touch -- Low-level local filesystem/OS security operation.
        }
        $steps['storage'] = [
            'ok'                 => @is_dir($storage) && @is_writable($storage), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Low-level local filesystem/OS security operation.
            'storage_dir'        => $storage,
            'events_file_exists' => @file_exists($events_file), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        ];

        // Step 2: Merge and persist safe security defaults.
        $requested_mode = strtolower(trim((string) ($options['waf_mode'] ?? 'monitor')));
        $waf_mode       = in_array($requested_mode, ['monitor', 'block', 'off'], true) ? $requested_mode : 'monitor';

        if (function_exists('update_option')) {
            $current = function_exists('get_option') ? Settings::all() : Settings::defaults();
            $merged  = array_merge($current, [
                'headers_enabled'       => 1,
                'block_xmlrpc'          => 1,
                'login_protection'      => 1,
                'integrity_enabled'     => 1,
                'waf_mode'              => $waf_mode,
                'waf_enabled'           => ('block' === $waf_mode) ? 1 : 0,
                'auto_ban_enabled'      => 1,
                'signature_auto_update' => 1,
                'malware_auto_scan'     => 1,
                'wizard_completed_at'   => $completed_at,
            ]);
            update_option(Settings::OPTION, $merged);
            $steps['settings'] = [
                'ok'       => true,
                'waf_mode' => $waf_mode,
            ];
        } else {
            $steps['settings'] = [
                'ok'       => true,
                'skipped'  => true,
                'waf_mode' => $waf_mode,
                'reason'   => 'WordPress options API unavailable',
            ];
        }

        // Step 3: Sync signatures feed to disk.
        $sync_wp       = (bool) ($options['sync_wp_checksums'] ?? true);
        $sig_result    = SignatureFeed::update(['sync_wp_checksums' => $sync_wp], $storage);
        $steps['signatures'] = [
            'ok'           => !empty($sig_result['last_updated']),
            'version'      => (string) ($sig_result['version'] ?? ''),
            'last_updated' => (string) ($sig_result['last_updated'] ?? ''),
            'counts'       => (array) ($sig_result['counts'] ?? []),
        ];

        // Step 4: Schedule WP-Cron hooks if absent.
        if (function_exists('wp_schedule_event') && function_exists('wp_next_scheduled')) {
            $cron_specs = [
                FileIntegrity::CRON_HOOK => 'hourly',
                EventMonitor::CRON_HOOK  => 'gratis_five_minutes',
                MalwareScanner::CRON_HOOK => 'daily',
                SignatureFeed::CRON_HOOK => 'daily',
            ];
            $scheduled = [];
            $now       = time();
            foreach ($cron_specs as $hook => $recurrence) {
                if (!wp_next_scheduled($hook)) {
                    wp_schedule_event($now + 60, $recurrence, $hook);
                    $scheduled[] = $hook;
                }
            }
            $steps['cron'] = [
                'ok'        => true,
                'scheduled' => $scheduled,
            ];
        } else {
            $steps['cron'] = [
                'ok'      => true,
                'skipped' => true,
                'reason'  => 'WordPress cron API unavailable',
            ];
        }

        // Step 5: Purge manifest-verified false-positive FIM detections.
        $purge_res       = EventMonitor::purge_verified_detections($root, $storage);
        $steps['cleanup'] = [
            'ok'        => true,
            'removed'   => (int) ($purge_res['removed'] ?? 0),
            'remaining' => (int) ($purge_res['remaining'] ?? 0),
        ];

        $run_scans = (bool) ($options['run_scans'] ?? true);

        // Step 6: Run FileIntegrity::scan() when full WP runtime APIs are available.
        if (
            $run_scans
            && function_exists('wp_upload_dir')
            && function_exists('wp_remote_get')
            && function_exists('get_locale')
        ) {
            $fim_res          = FileIntegrity::scan();
            $steps['fim_scan'] = [
                'ok'            => true,
                'engine'        => (string) ($fim_res['engine'] ?? ''),
                'total_checked' => (int) ($fim_res['total_checked'] ?? 0),
                'modified'      => (int) ($fim_res['modified_count'] ?? 0),
            ];
        } else {
            $steps['fim_scan'] = [
                'ok'      => true,
                'skipped' => true,
                'reason'  => $run_scans ? 'WordPress runtime APIs unavailable in CLI context' : 'Disabled via run_scans=false',
            ];
        }

        // Step 7: Run MalwareScanner::scan().
        if ($run_scans) {
            $scan_dir  = isset($options['scan_dir']) ? (string) $options['scan_dir'] : null;
            $mal_res   = MalwareScanner::scan($scan_dir, [
                'storage_dir'  => $storage,
                'project_root' => $root,
                'time_budget'  => 15.0,
            ]);
            $steps['malware_scan'] = [
                'ok'       => true,
                'scanned'  => (int) ($mal_res['scanned'] ?? 0),
                'findings' => count((array) ($mal_res['findings'] ?? [])),
                'counts'   => (array) ($mal_res['counts'] ?? []),
            ];
        } else {
            $steps['malware_scan'] = [
                'ok'      => true,
                'skipped' => true,
                'reason'  => 'Disabled via run_scans=false',
            ];
        }

        $audit = SecurityAudit::run($root, $storage);

        return [
            'ok'           => true,
            'steps'        => $steps,
            'audit'        => $audit,
            'completed_at' => $completed_at,
        ];
    }

    /**
     * @param array<string,mixed> $recs
     * @return array<int,array<string,string>>
     */
    private static function build_optional_os_upgrades(array $recs): array {
        $upgrades = [];

        if (!empty($recs['install'])) {
            $upgrades[] = [
                'id'         => 'os_packages',
                'title'      => 'Install OS security monitoring packages (auditd / inotify-tools)',
                'command'    => (string) $recs['install'],
                'why_manual' => 'Requires root package manager privileges (`sudo dnf` / `sudo apt-get`).',
            ];
        }
        if (!empty($recs['auditd'])) {
            $upgrades[] = [
                'id'         => 'auditd_rules',
                'title'      => 'Enable Linux kernel auditd syscall watch rules',
                'command'    => (string) $recs['auditd'],
                'why_manual' => 'Requires root (`CAP_AUDIT_CONTROL`) to load kernel audit rules.',
            ];
        }
        if (!empty($recs['inotify'])) {
            $upgrades[] = [
                'id'         => 'gratis_fim_service',
                'title'      => 'Install real-time inotifywait systemd watcher service',
                'command'    => (string) $recs['inotify'],
                'why_manual' => 'Zero-CPU real-time kernel daemon on top of PHP monitoring; requires root to register a systemd unit.',
            ];
        }
        if (!empty($recs['cron'])) {
            $upgrades[] = [
                'id'         => 'system_cron',
                'title'      => 'Register deterministic system cron for log trailing',
                'command'    => (string) $recs['cron'],
                'why_manual' => 'Requires root to write `/etc/cron.d/gratis-security` when running independent of web traffic.',
            ];
        }
        if (!empty($recs['aide'])) {
            $upgrades[] = [
                'id'         => 'aide_integrity',
                'title'      => 'Optional AIDE binary integrity database',
                'command'    => (string) $recs['aide'],
                'why_manual' => 'Requires root privileges to initialize and store OS-level AIDE databases.',
            ];
        }

        return $upgrades;
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

    private static function ensure_hardened_storage(string $storage): void {
        if (!@is_dir($storage)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            if (function_exists('wp_mkdir_p')) {
                wp_mkdir_p($storage);
            } else {
                @mkdir($storage, 0755, true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Low-level local filesystem/OS security operation.
            }
        }
        $htaccess = $storage . '/.htaccess';
        if (!@file_exists($htaccess)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            @file_put_contents($htaccess, "Require all denied\nDeny from all\n"); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
        }
        $index = $storage . '/index.php';
        if (!@file_exists($index)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
        }
    }
}
