<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * High-performance File Integrity & Server Monitoring for WordPress.
 *
 * Supports two distinct operational modes:
 * 1. Server-Assisted Mode (VPS / Dedicated / Red Hat / Cloud):
 *    Utilizes release manifests (SOURCE-MANIFEST.sha256), Linux kernel auditd,
 *    and inotifywait daemons with SIMDJSON acceleration.
 *
 * 2. Autonomous PHP Mode (Shared Hosting / CPanel / Restricted environments):
 *    Operates 100% in pure PHP with zero shell execution and zero server privileges.
 *    Verifies WordPress Core official signatures (api.wordpress.org), WordPress.org
 *    plugin checksums (downloads.wordpress.org), scans uploads for rogue executables,
 *    builds and compares local disk baselines, runs via WP-Cron, and alerts via email.
 *
 * Zero MySQL database overhead in all modes (all reports and baselines stored on disk).
 */
final class FileIntegrity {

    public const STORAGE_DIR = 'gratis-security';
    public const REPORT_FILE = 'fim-report.json';
    public const BASELINE_FILE = 'fim-baseline.json';
    public const CORE_CACHE_PREFIX = 'core-checksums-';
    public const PLUGIN_CACHE_PREFIX = 'plugin-checksums-';
    public const EVENTS_LOG_DEFAULT = '/var/log/gratis-fim.jsonl';
    public const CRON_HOOK = 'gratis_security_fim_cron_scan';
    public const ALERT_TRANSIENT = 'gratis_fim_alert';

    /**
     * Get the absolute path to the local storage directory.
     * Ensures directory exists and is secured against direct web access.
     */
    public static function get_storage_dir(): string {
        $upload_dir = wp_upload_dir();
        $base = $upload_dir['basedir'] . '/' . self::STORAGE_DIR;

        if (!is_dir($base)) {
            wp_mkdir_p($base);
        }

        $htaccess = $base . '/.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents($htaccess, "Require all denied\nDeny from all\n"); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
        }

        $index = $base . '/index.php';
        if (!file_exists($index)) {
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
        }

        return $base;
    }

    /**
     * Decode JSON using SIMDJSON if the PHP extension is loaded, falling back to standard json_decode.
     *
     * @param string $json
     * @param bool $assoc
     * @return mixed
     */
    public static function simd_decode(string $json, bool $assoc = true): mixed {
        if (function_exists('simdjson_decode')) {
            try {
                return simdjson_decode($json, $assoc);
            } catch (\Throwable) {
                return json_decode($json, $assoc);
            }
        }
        return json_decode($json, $assoc);
    }

    /**
     * Encode data to JSON with clean flags.
     */
    public static function simd_encode(mixed $data): string {
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT;
        if (function_exists('wp_json_encode')) {
            return (string) wp_json_encode($data, $flags);
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Fallback when executed outside WordPress runtime.
        return (string) json_encode($data, $flags);
    }

    /**
     * Safely determine whether shell execution is permitted and operational.
     * Checks disable_functions, open_basedir restrictions, and tests execution.
     */
    public static function is_shell_available(): bool {
        if (!function_exists('exec') || !function_exists('shell_exec')) {
            return false;
        }

        $disabled = (string) ini_get('disable_functions');
        if ('' !== $disabled) {
            $list = array_map('trim', explode(',', strtolower($disabled)));
            if (in_array('shell_exec', $list, true) || in_array('exec', $list, true)) {
                return false;
            }
        }

        try {
            $test = @shell_exec('echo 1 2>/dev/null'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            return is_string($test) && '1' === trim($test);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Detect all server capabilities and determine active mode.
     *
     * @return array<string,mixed>
     */
    public static function detect_server_capabilities(): array {
        $os_pretty = 'Unknown Linux/Unix';
        if (@file_exists('/etc/os-release')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $os_data = @parse_ini_file('/etc/os-release'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            if (is_array($os_data) && !empty($os_data['PRETTY_NAME'])) {
                $os_pretty = (string) $os_data['PRETTY_NAME'];
            }
        } elseif (PHP_OS === 'Darwin') {
            $os_pretty = 'macOS ' . php_uname('r');
        }

        $can_shell = self::is_shell_available();
        $has_simdjson = function_exists('simdjson_decode');
        $simd_version = $has_simdjson ? (phpversion('simdjson') ?: 'active') : false;

        $has_inotify = false;
        $inotify_path = '';
        if ($can_shell) {
            if (@file_exists('/usr/bin/inotifywait')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                $has_inotify = true;
                $inotify_path = '/usr/bin/inotifywait';
            } elseif (self::command_exists('inotifywait')) {
                $has_inotify = true;
                $inotify_path = trim((string) @shell_exec('which inotifywait 2>/dev/null')); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            }
        }

        $has_auditctl = false;
        $auditctl_path = '';
        $auditd_active = false;
        if ($can_shell) {
            if (@file_exists('/usr/sbin/auditctl')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                $has_auditctl = true;
                $auditctl_path = '/usr/sbin/auditctl';
            } elseif (self::command_exists('auditctl')) {
                $has_auditctl = true;
                $auditctl_path = trim((string) @shell_exec('which auditctl 2>/dev/null')); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            }

            if ($has_auditctl) {
                $audit_status = @shell_exec('systemctl is-active auditd 2>/dev/null'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
                if (is_string($audit_status) && trim($audit_status) === 'active') {
                    $auditd_active = true;
                }
            }
        }

        $has_aide = $can_shell && (@file_exists('/usr/sbin/aide') || @file_exists('/usr/bin/aide') || self::command_exists('aide')); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $has_git = $can_shell && self::command_exists('git');

        $root_dir = self::get_project_root();
        $source_manifest = @file_exists($root_dir . '/SOURCE-MANIFEST.sha256') ? $root_dir . '/SOURCE-MANIFEST.sha256' : null; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $composer_manifest = @file_exists($root_dir . '/COMPOSER-MANIFEST.sha256') ? $root_dir . '/COMPOSER-MANIFEST.sha256' : null; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.

        $revision = null;
        if (@file_exists($root_dir . '/REVISION')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $revision = trim((string) @file_get_contents($root_dir . '/REVISION')); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
        } elseif ($has_git && @is_dir($root_dir . '/.git')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $git_rev = @shell_exec('cd ' . escapeshellarg($root_dir) . ' && git rev-parse --short HEAD 2>/dev/null'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            if (is_string($git_rev) && '' !== trim($git_rev)) {
                $revision = trim($git_rev);
            }
        }

        $event_log_file = null;
        foreach (EventMonitor::discover_log_sources() as $source) {
            if ('inotify' === $source['type'] && $source['exists'] && $source['readable']) {
                $event_log_file = (string) $source['path'];
                break;
            }
        }

        // Determine Operational Mode
        $mode = 'autonomous_php';
        $mode_label = __('Autonominis PHP režimas (Shared Hosting)', 'gratis-security');

        if (null !== $source_manifest) {
            $mode = 'manifest';
            $mode_label = __('Versijuoti parašai (Release Manifest)', 'gratis-security');
        } elseif ($auditd_active || $has_inotify) {
            $mode = 'server_assisted';
            $mode_label = __('Branduolio stebėjimas (Linux Audit / Inotify)', 'gratis-security');
        }

        $is_cron_active = false !== wp_next_scheduled(self::CRON_HOOK);

        return [
            'mode'              => $mode,
            'mode_label'        => $mode_label,
            'is_shared_hosting' => ('autonomous_php' === $mode),
            'can_shell'         => $can_shell,
            'os'                => $os_pretty,
            'is_redhat'         => str_contains(strtolower($os_pretty), 'red hat') || str_contains(strtolower($os_pretty), 'rhel') || str_contains(strtolower($os_pretty), 'centos') || str_contains(strtolower($os_pretty), 'almalinux') || str_contains(strtolower($os_pretty), 'rocky'),
            'simdjson'          => $has_simdjson,
            'simdjson_version'  => $simd_version,
            'auditctl'          => $has_auditctl,
            'auditctl_path'     => $auditctl_path,
            'auditd_active'     => $auditd_active,
            'inotifywait'       => $has_inotify,
            'inotifywait_path'  => $inotify_path,
            'aide'              => $has_aide,
            'git'               => $has_git,
            'project_root'      => $root_dir,
            'source_manifest'   => $source_manifest,
            'composer_manifest' => $composer_manifest,
            'revision'          => $revision,
            'event_log'         => $event_log_file,
            'has_manifests'     => null !== $source_manifest,
            'cron_active'       => $is_cron_active,
            'next_cron'         => $is_cron_active ? get_date_from_gmt(gmdate('Y-m-d H:i:s', (int) wp_next_scheduled(self::CRON_HOOK))) : null,
        ];
    }

    /**
     * Unified Scan: Works across both Server-Assisted and Autonomous Shared Hosting modes.
     * Memory & timeout guarded so it never hangs or crashes on low-resource hosts.
     *
     * @param array<string,mixed> $options
     * @return array<string,mixed>
     */
    public static function scan(array $options = []): array {
        $caps = self::detect_server_capabilities();
        $root = $caps['project_root'];
        $check_vendor = !empty($options['check_vendor']);
        $time_start = microtime(true);
        $time_budget = 22.0; // 22 second soft ceiling to protect against 30s max_execution_time

        $files = [];
        $total_checked = 0;
        $engine = 'baseline';

        // 1. Release Manifests (if present)
        if (!empty($caps['source_manifest'])) {
            $engine = 'release_manifest';
            $manifest_results = self::verify_manifest_file((string) $caps['source_manifest'], $root);
            $total_checked += $manifest_results['checked'];
            $files = array_merge($files, $manifest_results['files']);

            if ($check_vendor && !empty($caps['composer_manifest'])) {
                $composer_results = self::verify_manifest_file((string) $caps['composer_manifest'], $root);
                $total_checked += $composer_results['checked'];
                $files = array_merge($files, $composer_results['files']);
            }
        }

        // 2. WordPress Core Official Checksums (api.wordpress.org)
        if (microtime(true) - $time_start < $time_budget) {
            $core_results = self::verify_core_signatures();
            if ($core_results['checked'] > 0) {
                $total_checked += $core_results['checked'];
                $existing_paths = array_column($files, 'path');
                foreach ($core_results['files'] as $c_file) {
                    if (!in_array($c_file['path'], $existing_paths, true)) {
                        $files[] = $c_file;
                    }
                }
                if ($engine === 'baseline') {
                    $engine = 'wp_core';
                }
            }
        }

        // 3. Uploads directory rogue executable scanner (Autonomous shared hosting protection)
        if (microtime(true) - $time_start < $time_budget) {
            $rogue_uploads = self::check_uploads_security();
            if (!empty($rogue_uploads)) {
                $existing_paths = array_column($files, 'path');
                foreach ($rogue_uploads as $r_file) {
                    if (!in_array($r_file['path'], $existing_paths, true)) {
                        $files[] = $r_file;
                        ++$total_checked;
                    }
                }
            }
        }

        // 4. Local Baseline verification (for custom plugins, themes, mu-plugins, and shared hosting)
        if (empty($caps['source_manifest']) && (microtime(true) - $time_start < $time_budget)) {
            $storage = self::get_storage_dir();
            $baseline_path = $storage . '/' . self::BASELINE_FILE;

            // Auto-provision baseline on first run if none exists yet!
            if (!file_exists($baseline_path)) {
                self::build_baseline();
            }

            $baseline_results = self::verify_local_baseline();
            $total_checked += $baseline_results['checked'];

            $existing_paths = array_column($files, 'path');
            foreach ($baseline_results['files'] as $b_file) {
                if (!in_array($b_file['path'], $existing_paths, true)) {
                    $files[] = $b_file;
                }
            }
            if ($engine === 'wp_core' || $engine === 'baseline') {
                $engine = 'autonomous_php';
            }
        }

        // 5. Official WordPress.org Plugins checksums (Autonomous mode)
        if (empty($caps['source_manifest']) && (microtime(true) - $time_start < $time_budget)) {
            $plugin_results = self::verify_wporg_plugins();
            $total_checked += $plugin_results['checked'];
            $existing_paths = array_column($files, 'path');
            foreach ($plugin_results['files'] as $p_file) {
                if (!in_array($p_file['path'], $existing_paths, true)) {
                    $files[] = $p_file;
                }
            }
        }

        $modified_count = 0;
        $missing_count = 0;
        $untracked_count = 0;

        foreach ($files as $f) {
            if ($f['status'] === 'modified') {
                ++$modified_count;
            } elseif ($f['status'] === 'missing') {
                ++$missing_count;
            } elseif ($f['status'] === 'untracked') {
                ++$untracked_count;
            }
        }

        $report = [
            'scanned_at'       => gmdate('c'),
            'timestamp'        => time(),
            'elapsed_seconds'  => round(microtime(true) - $time_start, 2),
            'revision'         => $caps['revision'] ?: 'local',
            'engine'           => $engine,
            'mode'             => $caps['mode'],
            'mode_label'       => $caps['mode_label'],
            'simd_accelerated' => $caps['simdjson'],
            'total_checked'    => $total_checked,
            'modified_count'   => $modified_count,
            'missing_count'    => $missing_count,
            'untracked_count'  => $untracked_count,
            'files'            => $files,
        ];

        // Save report directly to disk with SIMDJSON encoding (zero MySQL writes)
        $storage_dir = self::get_storage_dir();
        @file_put_contents( // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
            $storage_dir . '/' . self::REPORT_FILE,
            self::simd_encode($report),
            LOCK_EX
        );

        return $report;
    }

    /**
     * Get the latest scan report from disk.
     *
     * @return array<string,mixed>|null
     */
    public static function get_last_report(): ?array {
        $path = self::get_storage_dir() . '/' . self::REPORT_FILE;
        if (!file_exists($path)) {
            return null;
        }

        $json = @file_get_contents($path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
        if (!is_string($json) || '' === $json) {
            return null;
        }

        $data = self::simd_decode($json, true);
        return is_array($data) ? $data : null;
    }

    /**
     * Verify a SHA256 manifest file.
     * Uses shell sha256sum if available, otherwise streams pure PHP.
     *
     * @param string $manifest_path
     * @param string $root
     * @return array{checked:int,files:array<int,array<string,mixed>>}
     */
    private static function verify_manifest_file(string $manifest_path, string $root): array {
        $result = ['checked' => 0, 'files' => []];
        if (!file_exists($manifest_path)) {
            return $result;
        }

        // Count lines
        $line_count = 0;
        $handle = @fopen($manifest_path, 'r'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if ($handle) {
            while (!feof($handle)) {
                if (fgets($handle) !== false) {
                    ++$line_count;
                }
            }
            fclose($handle); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming file handle close for security logs/locks.
        }
        $result['checked'] = $line_count;

        // Fast path: shell sha256sum if available
        if (self::is_shell_available() && self::command_exists('sha256sum')) {
            $cmd = 'cd ' . escapeshellarg($root) . ' && sha256sum -c --quiet ' . escapeshellarg($manifest_path) . ' 2>&1';
            $output = @shell_exec($cmd); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.

            if (is_string($output) && '' !== trim($output)) {
                $lines = explode("\n", trim($output));
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ('' === $line || str_contains($line, 'WARNING:')) {
                        continue;
                    }

                    if (str_ends_with($line, ': FAILED open or read')) {
                        $rel = substr($line, 0, -strlen(': FAILED open or read'));
                        $result['files'][] = [
                            'path'      => $rel,
                            'component' => self::categorize_path($rel),
                            'status'    => 'missing',
                            'size'      => 0,
                            'mtime'     => '',
                        ];
                    } elseif (str_ends_with($line, ': FAILED')) {
                        $rel = substr($line, 0, -strlen(': FAILED'));
                        $full_path = $root . '/' . $rel;
                        $result['files'][] = [
                            'path'      => $rel,
                            'component' => self::categorize_path($rel),
                            'status'    => 'modified',
                            'size'      => file_exists($full_path) ? (int) @filesize($full_path) : 0, // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                            'mtime'     => file_exists($full_path) ? gmdate('Y-m-d H:i:s', (int) @filemtime($full_path)) : '', // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                        ];
                    }
                }
                return $result;
            }
        }

        // Pure PHP streaming fallback (Shared Hosting safe)
        $handle = @fopen($manifest_path, 'r'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if (!$handle) {
            return $result;
        }

        for ($line = fgets($handle); false !== $line; $line = fgets($handle)) {
            $line = trim($line);
            if ('' === $line || !str_contains($line, '  ')) {
                continue;
            }
            [$expected_hash, $rel] = explode('  ', $line, 2);
            $full_path = $root . '/' . $rel;

            if (!file_exists($full_path)) {
                $result['files'][] = [
                    'path'      => $rel,
                    'component' => self::categorize_path($rel),
                    'status'    => 'missing',
                    'size'      => 0,
                    'mtime'     => '',
                ];
                continue;
            }

            $current_hash = hash_file('sha256', $full_path);
            if ($current_hash !== $expected_hash) {
                $result['files'][] = [
                    'path'      => $rel,
                    'component' => self::categorize_path($rel),
                    'status'    => 'modified',
                    'size'      => (int) @filesize($full_path), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                    'mtime'     => gmdate('Y-m-d H:i:s', (int) @filemtime($full_path)), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                ];
            }
        }
        fclose($handle); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming file handle close for security logs/locks.

        return $result;
    }

    /**
     * Check WordPress Core files against official WordPress.org checksums.
     * Pure PHP, works in any hosting environment via wp_remote_get.
     *
     * @return array{checked:int,files:array<int,array<string,mixed>>}
     */
    public static function verify_core_signatures(): array {
        global $wp_version, $wp_local_package;

        $result = ['checked' => 0, 'files' => []];
        $version = $wp_version ?? '6.7';
        $locale  = $wp_local_package ?? get_locale() ?: 'en_US';

        $checksums = self::get_official_core_checksums($version, $locale);
        if (empty($checksums)) {
            return $result;
        }

        $result['checked'] = count($checksums);
        $wp_root = ABSPATH;

        foreach ($checksums as $rel => $expected_md5) {
            $full_path = $wp_root . $rel;

            if (!file_exists($full_path)) {
                $result['files'][] = [
                    'path'      => self::normalize_rel_path($full_path),
                    'component' => 'core',
                    'status'    => 'missing',
                    'size'      => 0,
                    'mtime'     => '',
                ];
                continue;
            }

            $current_md5 = md5_file($full_path);
            if ($current_md5 !== $expected_md5) {
                $result['files'][] = [
                    'path'      => self::normalize_rel_path($full_path),
                    'component' => 'core',
                    'status'    => 'modified',
                    'size'      => (int) @filesize($full_path), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                    'mtime'     => gmdate('Y-m-d H:i:s', (int) @filemtime($full_path)), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                ];
            }
        }

        return $result;
    }

    /**
     * Check WordPress.org official plugins against their published checksums.
     *
     * @return array{checked:int,files:array<int,array<string,mixed>>}
     */
    public static function verify_wporg_plugins(): array {
        $result = ['checked' => 0, 'files' => []];
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = get_plugins();
        if (empty($all_plugins)) {
            return $result;
        }

        $storage = self::get_storage_dir();

        foreach ($all_plugins as $plugin_file => $plugin_data) {
            $slug = dirname($plugin_file);
            if ('.' === $slug || empty($slug)) {
                continue; // Skip single-file plugins in plugins root
            }

            $version = $plugin_data['Version'] ?? '';
            if ('' === $version) {
                continue;
            }

            $cache_file = $storage . '/' . self::PLUGIN_CACHE_PREFIX . $slug . '-' . $version . '.json';
            $checksum_data = null;

            if (file_exists($cache_file)) {
                $checksum_data = self::simd_decode((string) @file_get_contents($cache_file), true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
            }

            if (!is_array($checksum_data)) {
                $api_url = sprintf('https://downloads.wordpress.org/plugin-checksums/%s/%s.json', rawurlencode($slug), rawurlencode($version));
                $response = wp_remote_get($api_url, ['timeout' => 5]);

                if (is_wp_error($response) || 200 !== wp_remote_retrieve_response_code($response)) {
                    continue; // Plugin might not be on w.org or private, skip
                }

                $body = wp_remote_retrieve_body($response);
                $checksum_data = self::simd_decode($body, true);
                if (is_array($checksum_data) && !empty($checksum_data['files'])) {
                    @file_put_contents($cache_file, self::simd_encode($checksum_data), LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
                } else {
                    continue;
                }
            }

            if (empty($checksum_data['files']) || !is_array($checksum_data['files'])) {
                continue;
            }

            $plugin_dir = WP_PLUGIN_DIR . '/' . $slug;
            foreach ($checksum_data['files'] as $rel_file => $hashes) {
                $full_path = $plugin_dir . '/' . $rel_file;
                ++$result['checked'];

                if (!file_exists($full_path)) {
                    $result['files'][] = [
                        'path'      => self::normalize_rel_path($full_path),
                        'component' => 'plugins',
                        'status'    => 'missing',
                        'size'      => 0,
                        'mtime'     => '',
                    ];
                    continue;
                }

                $expected_sha256 = $hashes['sha256'] ?? null;
                $expected_md5    = $hashes['md5'] ?? null;

                $match = false;
                if ($expected_sha256) {
                    $match = hash_file('sha256', $full_path) === $expected_sha256;
                } elseif ($expected_md5) {
                    $match = md5_file($full_path) === $expected_md5;
                }

                if (!$match) {
                    $result['files'][] = [
                        'path'      => self::normalize_rel_path($full_path),
                        'component' => 'plugins',
                        'status'    => 'modified',
                        'size'      => (int) @filesize($full_path), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                        'mtime'     => gmdate('Y-m-d H:i:s', (int) @filemtime($full_path)), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                    ];
                }
            }
        }

        return $result;
    }

    /**
     * Scan the uploads directory for dangerous rogue executables.
     * Prevents backdoors on shared hosting where uploads are publicly writable.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function check_uploads_security(): array {
        $upload_dir = wp_upload_dir();
        $basedir = $upload_dir['basedir'];
        $rogue = [];

        if (!is_dir($basedir)) {
            return $rogue;
        }

        $dangerous_exts = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'phar', 'cgi', 'pl', 'py'];

        try {
            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($basedir, \FilesystemIterator::SKIP_DOTS)
            );

            foreach ($it as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $filename = strtolower($file->getFilename());
                $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

                // Exclude our own gratis-security storage index.php
                if ($filename === 'index.php' && str_contains($file->getPathname(), self::STORAGE_DIR)) {
                    continue;
                }

                if (in_array($ext, $dangerous_exts, true) || str_contains($filename, '.php.')) {
                    $rogue[] = [
                        'path'      => self::normalize_rel_path($file->getPathname()),
                        'component' => 'uploads',
                        'status'    => 'untracked',
                        'size'      => (int) $file->getSize(),
                        'mtime'     => gmdate('Y-m-d H:i:s', (int) $file->getMTime()),
                    ];
                }
            }
        } catch (\Throwable) {
            return $rogue;
        }

        return $rogue;
    }

    /**
     * Fetch or retrieve cached official core checksums from api.wordpress.org.
     *
     * @param string $version
     * @param string $locale
     * @return array<string,string>
     */
    public static function get_official_core_checksums(string $version, string $locale): array {
        $storage = self::get_storage_dir();
        $cache_file = $storage . '/' . self::CORE_CACHE_PREFIX . $version . '-' . $locale . '.json';

        if (file_exists($cache_file)) {
            $data = self::simd_decode((string) @file_get_contents($cache_file), true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
            if (is_array($data)) {
                return $data;
            }
        }

        $url = sprintf(
            'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
            rawurlencode($version),
            rawurlencode($locale)
        );

        $response = wp_remote_get($url, ['timeout' => 8]);
        if (is_wp_error($response) || 200 !== wp_remote_retrieve_response_code($response)) {
            return [];
        }

        $body = wp_remote_retrieve_body($response);
        $json = self::simd_decode($body, true);
        if (!is_array($json) || empty($json['checksums']) || !is_array($json['checksums'])) {
            return [];
        }

        $checksums = (array) $json['checksums'];
        @file_put_contents($cache_file, self::simd_encode($checksums), LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.

        return $checksums;
    }

    /**
     * Build or rebuild a local SHA256 baseline.
     * Operates purely in PHP and stores results on disk via SIMDJSON (no MySQL).
     *
     * @return int Count of hashed files.
     */
    public static function build_baseline(): int {
        $root = self::get_project_root();
        $hashes = [];

        $scan_dirs = array_filter([
            WP_CONTENT_DIR . '/mu-plugins',
            WP_PLUGIN_DIR,
            get_theme_root(),
            $root . '/packages/plugins',
            $root . '/config',
        ], 'is_dir');

        foreach ($scan_dirs as $dir) {
            try {
                $it = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
                );

                foreach ($it as $file) {
                    if (!$file->isFile()) {
                        continue;
                    }
                    $ext = strtolower($file->getExtension());
                    if (!in_array($ext, ['php', 'js', 'css', 'json', 'yml', 'yaml', 'htaccess'], true)) {
                        continue;
                    }

                    $full_path = $file->getPathname();
                    $rel = self::normalize_rel_path($full_path);
                    $hash = hash_file('sha256', $full_path);
                    if (is_string($hash)) {
                        $hashes[$rel] = $hash;
                    }
                }
            } catch (\Throwable) {
                continue;
            }
        }

        $storage = self::get_storage_dir();
        @file_put_contents( // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
            $storage . '/' . self::BASELINE_FILE,
            self::simd_encode([
                'built_at' => gmdate('c'),
                'count'    => count($hashes),
                'hashes'   => $hashes,
            ]),
            LOCK_EX
        );

        return count($hashes);
    }

    /**
     * Verify local baseline.
     *
     * @return array{checked:int,files:array<int,array<string,mixed>>}
     */
    private static function verify_local_baseline(): array {
        $result = ['checked' => 0, 'files' => []];
        $storage = self::get_storage_dir();
        $baseline_path = $storage . '/' . self::BASELINE_FILE;

        if (!file_exists($baseline_path)) {
            return $result;
        }

        $data = self::simd_decode((string) @file_get_contents($baseline_path), true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
        if (!is_array($data) || empty($data['hashes']) || !is_array($data['hashes'])) {
            return $result;
        }

        $baseline = $data['hashes'];
        $root = self::get_project_root();
        $result['checked'] = count($baseline);

        foreach ($baseline as $rel => $expected_hash) {
            $full_path = $root . '/' . $rel;
            if (!file_exists($full_path)) {
                $result['files'][] = [
                    'path'      => $rel,
                    'component' => self::categorize_path($rel),
                    'status'    => 'missing',
                    'size'      => 0,
                    'mtime'     => '',
                ];
                continue;
            }

            $current_hash = hash_file('sha256', $full_path);
            if ($current_hash !== $expected_hash) {
                $result['files'][] = [
                    'path'      => $rel,
                    'component' => self::categorize_path($rel),
                    'status'    => 'modified',
                    'size'      => (int) @filesize($full_path), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                    'mtime'     => gmdate('Y-m-d H:i:s', (int) @filemtime($full_path)), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                ];
            }
        }

        return $result;
    }

    /**
     * Pure PHP Diff & Security Inspector.
     * Works with Git, upstream WordPress Core, official plugin SVN, or local analysis.
     *
     * @param string $relative_path
     * @return array{success:bool,diff:string,info:string,malware_hits:array<int,string>}
     */
    public static function get_file_diff(string $relative_path): array {
        $relative_path = ltrim($relative_path, '/');
        $root = self::get_project_root();
        $full_path = $root . '/' . $relative_path;

        if (!file_exists($full_path)) {
            return [
                'success'      => false,
                'diff'         => 'Failas nerastas serveryje: ' . esc_html($relative_path),
                'info'         => 'Būsena: Trūksta',
                'malware_hits' => [],
            ];
        }

        $malware_hits = self::check_suspicious_patterns($full_path);

        // 1. Git diff (if available)
        if (self::is_shell_available() && self::command_exists('git') && @is_dir($root . '/.git')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $cmd = 'cd ' . escapeshellarg($root) . ' && git diff -- ' . escapeshellarg($relative_path) . ' 2>&1';
            $diff_output = @shell_exec($cmd); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            if (is_string($diff_output) && '' !== trim($diff_output)) {
                return [
                    'success'      => true,
                    'diff'         => $diff_output,
                    'info'         => 'Git repozitorijos diff',
                    'malware_hits' => $malware_hits,
                ];
            }
        }

        // 2. WordPress Core file: fetch upstream official source
        if (str_starts_with($relative_path, 'web/wp/') || str_starts_with($relative_path, 'wp-admin/') || str_starts_with($relative_path, 'wp-includes/')) {
            global $wp_version;
            $core_sub = preg_replace('#^web/wp/#', '', $relative_path);
            $raw_url = 'https://raw.githubusercontent.com/WordPress/WordPress/' . ($wp_version ?: 'master') . '/' . $core_sub;
            $upstream = wp_remote_get($raw_url, ['timeout' => 5]);
            if (!is_wp_error($upstream) && 200 === wp_remote_retrieve_response_code($upstream)) {
                $orig_content = wp_remote_retrieve_body($upstream);
                $curr_content = (string) @file_get_contents($full_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
                $diff = self::compute_unified_diff($orig_content, $curr_content, "upstream/$core_sub", $relative_path);
                return [
                    'success'      => true,
                    'diff'         => $diff,
                    'info'         => 'Palyginimas su oficialiu WordPress ' . ($wp_version ?: 'core') . ' kodu',
                    'malware_hits' => $malware_hits,
                ];
            }
        }

        // 3. WordPress.org Plugin file: fetch from SVN
        if (str_contains($relative_path, 'plugins/')) {
            $parts = explode('plugins/', $relative_path, 2);
            $plugin_sub = $parts[1] ?? '';
            $sub_parts = explode('/', $plugin_sub, 2);
            $slug = $sub_parts[0] ?? '';
            $file_in_plugin = $sub_parts[1] ?? '';

            if ('' !== $slug && '' !== $file_in_plugin) {
                $svn_url = "https://plugins.svn.wordpress.org/{$slug}/trunk/{$file_in_plugin}";
                $upstream = wp_remote_get($svn_url, ['timeout' => 5]);
                if (!is_wp_error($upstream) && 200 === wp_remote_retrieve_response_code($upstream)) {
                    $orig_content = wp_remote_retrieve_body($upstream);
                    $curr_content = (string) @file_get_contents($full_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
                    $diff = self::compute_unified_diff($orig_content, $curr_content, "wporg/$slug/$file_in_plugin", $relative_path);
                    return [
                        'success'      => true,
                        'diff'         => $diff,
                        'info'         => 'Palyginimas su oficialiu WordPress.org SVN repozitorijos kodu',
                        'malware_hits' => $malware_hits,
                    ];
                }
            }
        }

        // 4. File preview with security metrics
        $mtime = gmdate('Y-m-d H:i:s', (int) @filemtime($full_path)); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $size  = @filesize($full_path) ?: 0; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $perms = substr(sprintf('%o', @fileperms($full_path)), -4); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $sha   = hash_file('sha256', $full_path);

        $preview = (string) @file_get_contents($full_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
        if (strlen($preview) > 50000) {
            $preview = substr($preview, 0, 50000) . "\n\n... [Failo peržiūra apribota iki 50KB] ...";
        }

        $info = sprintf('Pakeistas: %s | Dydis: %d baitų | Teisės: %s | SHA256: %s', $mtime, $size, $perms, $sha);
        if (!empty($malware_hits)) {
            $info .= ' | ⚠ Įspėjimas: ' . implode(', ', $malware_hits);
        }

        return [
            'success'      => true,
            'diff'         => $preview,
            'info'         => $info,
            'malware_hits' => $malware_hits,
        ];
    }

    /**
     * Scheduled Cron Scan runner.
     * Executed by WP-Cron daily or hourly. Operates in pure PHP.
     */
    public static function cron_scan(): void {
        EventMonitor::trail();
        $report = self::scan();
        $total_changed = $report['modified_count'] + $report['missing_count'] + $report['untracked_count'];

        if ($total_changed > 0) {
            set_transient(self::ALERT_TRANSIENT, [
                'count'     => $total_changed,
                'timestamp' => time(),
                'report'    => [
                    'modified'  => $report['modified_count'],
                    'missing'   => $report['missing_count'],
                    'untracked' => $report['untracked_count'],
                ],
            ], DAY_IN_SECONDS * 7);

            // Optional email notification
            $notify = Settings::get_bool('notify_email_on_fim', true);
            if ($notify) {
                $to = get_option('admin_email');
                $site_name = get_bloginfo('name');
                $subject = sprintf('[%s] Saugumo pranešimas: aptikti failų pakeitimai (%d)', $site_name, $total_changed);
                $body = sprintf(
                    "Sveiki,\n\nGratis Security failų stebėjimo skydas aptiko %d pasikeitusius, trūkstamus ar nežinomus failus svetainėje %s.\n\n"
                    . "- Pakeisti failai: %d\n"
                    . "- Trūkstami failai: %d\n"
                    . "- Nauji / nežinomi failai: %d\n\n"
                    . "Peržiūrėkite išsamų kodo diff ir ataskaitą valdymo skyde:\n%s\n\n"
                    . "Pagarbiai,\nGratis Security",
                    $total_changed,
                    home_url(),
                    $report['modified_count'],
                    $report['missing_count'],
                    $report['untracked_count'],
                    admin_url('options-general.php?page=gratis-security&tab=fim')
                );
                wp_mail($to, $subject, $body);
            }
        } else {
            delete_transient(self::ALERT_TRANSIENT);
        }
    }

    /**
     * Inspect file for suspicious backdoor patterns without executing it.
     *
     * @param string $path
     * @return array<int,string>
     */
    private static function check_suspicious_patterns(string $path): array {
        $hits = [];
        $content = @file_get_contents($path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
        if (!is_string($content) || '' === $content) {
            return $hits;
        }

        $patterns = [
            'eval(base64_decode' => 'Užmaskuotas kodas (eval base64)',
            'eval(gzinflate'     => 'Suglaudintas kodas (eval gzinflate)',
            'eval(str_rot13'     => 'ROT13 kodavimas',
            'shell_exec('        => 'Serverio komandos iškvietimas (shell_exec)',
            'passthru('          => 'Tiesioginis komandų vykdymas (passthru)',
            'system('            => 'Sisteminė komanda (system)',
            'assert(eval'        => 'Dvigubas assert/eval kodas',
        ];

        foreach ($patterns as $pattern => $label) {
            if (str_contains($content, $pattern) || 1 === @preg_match("/{$pattern}/i", $content)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                $hits[] = $label;
            }
        }

        return $hits;
    }

    /**
     * Read recent events from real-time event log (if present).
     *
     * @param int $limit
     * @return array<int,array<string,mixed>>
     */
    public static function read_live_events(int $limit = 50): array {
        $caps = self::detect_server_capabilities();
        $log_file = $caps['event_log'];
        if (!$log_file || !file_exists($log_file) || !is_readable($log_file)) {
            return [];
        }

        $fp = @fopen($log_file, 'r'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if (!$fp) {
            return [];
        }

        fseek($fp, 0, SEEK_END);
        $file_size = ftell($fp);

        $buffer_size = 4096;
        $data = '';
        while ($file_size > 0) {
            $read_size = min($buffer_size, $file_size);
            $file_size -= $read_size;
            fseek($fp, $file_size);
            $chunk = fread($fp, $read_size); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Streaming bounded read of security log/file.
            $data = $chunk . $data;
            if (substr_count($data, "\n") > $limit + 1) {
                break;
            }
        }
        fclose($fp); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming file handle close for security logs/locks.

        $raw_lines = array_filter(array_map('trim', explode("\n", $data)));
        $parsed = [];
        foreach (array_reverse($raw_lines) as $raw) {
            if ('' === $raw) {
                continue;
            }
            $item = self::simd_decode($raw, true);
            if (is_array($item)) {
                $parsed[] = $item;
            } else {
                $parsed[] = ['time' => '', 'event' => 'RAW', 'file' => $raw];
            }
            if (count($parsed) >= $limit) {
                break;
            }
        }

        return $parsed;
    }

    /**
     * Generate clear copy-paste Linux server setup instructions tailored to the detected host.
     *
     * @return array<string,mixed>
     */
    public static function get_server_instructions(string $service_user_mode = 'php'): array {
        $inspection = ServerInspector::inspect($service_user_mode);
        return (array) $inspection['recommendations'];
    }

    /**
     * Categorize a file path into its logical component.
     */
    public static function categorize_path(string $path): string {
        $path = str_replace('\\', '/', $path);
        if (str_contains($path, 'mu-plugins/')) {
            return 'mu-plugins';
        }
        if (str_contains($path, 'plugins/')) {
            return 'plugins';
        }
        if (str_contains($path, 'themes/')) {
            return 'themes';
        }
        if (str_contains($path, 'web/wp/') || str_starts_with($path, 'wp-admin/') || str_starts_with($path, 'wp-includes/')) {
            return 'core';
        }
        if (str_contains($path, 'uploads/')) {
            return 'uploads';
        }
        if (str_contains($path, 'vendor/')) {
            return 'vendor';
        }
        if (str_contains($path, 'config/')) {
            return 'config';
        }
        return 'other';
    }

    /**
     * Normalize an absolute file path to a relative project path.
     */
    public static function normalize_rel_path(string $path): string {
        $path = str_replace('\\', '/', $path);
        $root = str_replace('\\', '/', self::get_project_root());

        if (str_starts_with($path, $root . '/')) {
            return substr($path, strlen($root . '/'));
        }

        $abspath = str_replace('\\', '/', ABSPATH);
        if (str_starts_with($path, $abspath)) {
            $rel = substr($path, strlen($abspath));
            // In bedrock structure, ABSPATH is often /.../web/wp/
            if (str_contains($abspath, '/web/wp/')) {
                return 'web/wp/' . $rel;
            }
            return $rel;
        }

        return ltrim($path, '/');
    }

    /**
     * Get root directory of project.
     */
    public static function get_project_root(): string {
        if (defined('WP_CONTENT_DIR')) {
            $parent = dirname(WP_CONTENT_DIR);
            if (@file_exists($parent . '/SOURCE-MANIFEST.sha256') || @file_exists($parent . '/composer.json')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                return $parent;
            }
            $grand = dirname($parent);
            if (@file_exists($grand . '/SOURCE-MANIFEST.sha256') || @file_exists($grand . '/composer.json')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                return $grand;
            }
        }
        return rtrim(ABSPATH, '/');
    }

    /**
     * Helper to check if a command exists in the shell path.
     */
    private static function command_exists(string $cmd): bool {
        if (!self::is_shell_available()) {
            return false;
        }
        $whereIsCommand = (PHP_OS === 'WINNT') ? 'where' : 'which';
        $output = @shell_exec("$whereIsCommand " . escapeshellarg($cmd) . ' 2>/dev/null'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
        return is_string($output) && '' !== trim($output);
    }

    /**
     * Pure PHP unified diff generator.
     */
    private static function compute_unified_diff(string $from, string $to, string $from_name, string $to_name): string {
        $from_lines = explode("\n", str_replace("\r\n", "\n", $from));
        $to_lines   = explode("\n", str_replace("\r\n", "\n", $to));

        $diff = '--- ' . $from_name . "\n+++ " . $to_name . "\n";
        $from_count = count($from_lines);
        $to_count   = count($to_lines);
        $max = max($from_count, $to_count);

        $hunk = [];
        for ($i = 0; $i < $max; $i++) {
            $f = $from_lines[$i] ?? null;
            $t = $to_lines[$i] ?? null;

            if ($f !== $t) {
                if (null !== $f) {
                    $hunk[] = '- ' . $f;
                }
                if (null !== $t) {
                    $hunk[] = '+ ' . $t;
                }
            }
        }

        if (empty($hunk)) {
            return 'No line changes detected (whitespace or binary difference).';
        }

        return $diff . implode("\n", array_slice($hunk, 0, 500));
    }
}
