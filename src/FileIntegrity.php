<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * High-performance File Integrity & Server Monitoring for WordPress.
 *
 * Verifies versioned release signatures (SOURCE-MANIFEST.sha256, COMPOSER-MANIFEST.sha256),
 * checks WordPress Core official checksums (api.wordpress.org), interfaces with
 * server-level monitoring (Red Hat auditd, inotifywait), and uses SIMD-accelerated
 * JSON parsing for zero MySQL database overhead.
 */
final class FileIntegrity {

    public const STORAGE_DIR = 'gratis-security';
    public const REPORT_FILE = 'fim-report.json';
    public const BASELINE_FILE = 'fim-baseline.json';
    public const CORE_CACHE_PREFIX = 'core-checksums-';
    public const EVENTS_LOG_DEFAULT = '/var/log/gratis-fim.jsonl';

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
            file_put_contents($htaccess, "Require all denied\nDeny from all\n");
        }

        $index = $base . '/index.php';
        if (!file_exists($index)) {
            file_put_contents($index, "<?php\n// Silence is golden.\n");
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
                // Fallback to native json_decode if simdjson fails
            }
        }
        return json_decode($json, $assoc);
    }

    /**
     * Encode data to JSON with clean flags.
     */
    public static function simd_encode(mixed $data): string {
        return (string) json_encode(
            $data,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
        );
    }

    /**
     * Detect all server-level capabilities: OS, auditd, inotifywait, SIMDJSON, release manifests, git.
     *
     * @return array<string,mixed>
     */
    public static function detect_server_capabilities(): array {
        $os_pretty = 'Unknown Linux/Unix';
        if (file_exists('/etc/os-release')) {
            $os_data = parse_ini_file('/etc/os-release');
            if (is_array($os_data) && !empty($os_data['PRETTY_NAME'])) {
                $os_pretty = (string) $os_data['PRETTY_NAME'];
            }
        } elseif (PHP_OS === 'Darwin') {
            $os_pretty = 'macOS ' . php_uname('r');
        }

        $has_simdjson = function_exists('simdjson_decode');
        $simd_version = $has_simdjson ? (phpversion('simdjson') ?: 'active') : false;

        $has_inotify = false;
        $inotify_path = '';
        if (file_exists('/usr/bin/inotifywait')) {
            $has_inotify = true;
            $inotify_path = '/usr/bin/inotifywait';
        } elseif (self::command_exists('inotifywait')) {
            $has_inotify = true;
            $inotify_path = trim((string) shell_exec('which inotifywait 2>/dev/null'));
        }

        $has_auditctl = false;
        $auditctl_path = '';
        $auditd_active = false;
        if (file_exists('/usr/sbin/auditctl')) {
            $has_auditctl = true;
            $auditctl_path = '/usr/sbin/auditctl';
        } elseif (self::command_exists('auditctl')) {
            $has_auditctl = true;
            $auditctl_path = trim((string) shell_exec('which auditctl 2>/dev/null'));
        }

        if ($has_auditctl) {
            $audit_status = shell_exec('systemctl is-active auditd 2>/dev/null');
            if (is_string($audit_status) && trim($audit_status) === 'active') {
                $auditd_active = true;
            }
        }

        $has_aide = file_exists('/usr/sbin/aide') || file_exists('/usr/bin/aide') || self::command_exists('aide');

        $root_dir = self::get_project_root();
        $source_manifest = file_exists($root_dir . '/SOURCE-MANIFEST.sha256') ? $root_dir . '/SOURCE-MANIFEST.sha256' : null;
        $composer_manifest = file_exists($root_dir . '/COMPOSER-MANIFEST.sha256') ? $root_dir . '/COMPOSER-MANIFEST.sha256' : null;

        $revision = null;
        if (file_exists($root_dir . '/REVISION')) {
            $revision = trim((string) file_get_contents($root_dir . '/REVISION'));
        } elseif (is_dir($root_dir . '/.git') && self::command_exists('git')) {
            $git_rev = shell_exec('cd ' . escapeshellarg($root_dir) . ' && git rev-parse --short HEAD 2>/dev/null');
            if (is_string($git_rev) && '' !== trim($git_rev)) {
                $revision = trim($git_rev);
            }
        }

        $event_log_file = null;
        if (file_exists(self::EVENTS_LOG_DEFAULT) && is_readable(self::EVENTS_LOG_DEFAULT)) {
            $event_log_file = self::EVENTS_LOG_DEFAULT;
        } else {
            $shared_log = dirname($root_dir, 2) . '/shared/gratis-fim.jsonl';
            if (file_exists($shared_log) && is_readable($shared_log)) {
                $event_log_file = $shared_log;
            }
        }

        return [
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
            'git'               => self::command_exists('git'),
            'project_root'      => $root_dir,
            'source_manifest'   => $source_manifest,
            'composer_manifest' => $composer_manifest,
            'revision'          => $revision,
            'event_log'         => $event_log_file,
            'has_manifests'     => null !== $source_manifest,
        ];
    }

    /**
     * Run full scan: checks release manifests, WP core checksums, or local baseline.
     * Saves the resulting report to disk with SIMDJSON, bypassing MySQL entirely.
     *
     * @param array<string,mixed> $options
     * @return array<string,mixed>
     */
    public static function scan(array $options = []): array {
        $caps = self::detect_server_capabilities();
        $root = $caps['project_root'];
        $check_vendor = !empty($options['check_vendor']);

        $files = [];
        $total_checked = 0;
        $engine = 'baseline';

        // 1. If release manifests exist, verify against them (authoritative versioned signatures)
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

        // 2. Also check WP Core against official WordPress.org checksums API
        $core_results = self::verify_core_signatures();
        if ($core_results['checked'] > 0) {
            $total_checked += $core_results['checked'];
            // Merge core changed files avoiding duplicates
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

        // 3. Fallback to local baseline if no manifests were available
        if (empty($caps['source_manifest']) && empty($files)) {
            $baseline_results = self::verify_local_baseline();
            $total_checked += $baseline_results['checked'];
            $files = array_merge($files, $baseline_results['files']);
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
            'revision'         => $caps['revision'] ?: 'local',
            'engine'           => $engine,
            'simd_accelerated' => $caps['simdjson'],
            'total_checked'    => $total_checked,
            'modified_count'   => $modified_count,
            'missing_count'    => $missing_count,
            'untracked_count'  => $untracked_count,
            'files'            => $files,
        ];

        // Save report to disk with SIMDJSON encoding
        $storage_dir = self::get_storage_dir();
        file_put_contents(
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

        $json = file_get_contents($path);
        if (!is_string($json) || '' === $json) {
            return null;
        }

        $data = self::simd_decode($json, true);
        return is_array($data) ? $data : null;
    }

    /**
     * Verify a SHA256 manifest file (format: "<sha256>  <relative_path>").
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

        // Count total lines
        $line_count = 0;
        $handle = fopen($manifest_path, 'r');
        if ($handle) {
            while (!feof($handle)) {
                if (fgets($handle) !== false) {
                    ++$line_count;
                }
            }
            fclose($handle);
        }
        $result['checked'] = $line_count;

        // If sha256sum binary is available, use it via shell for max speed
        if (self::command_exists('sha256sum')) {
            $cmd = 'cd ' . escapeshellarg($root) . ' && sha256sum -c --quiet ' . escapeshellarg($manifest_path) . ' 2>&1';
            $output = shell_exec($cmd);

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
                            'size'      => file_exists($full_path) ? (int) filesize($full_path) : 0,
                            'mtime'     => file_exists($full_path) ? gmdate('Y-m-d H:i:s', (int) filemtime($full_path)) : '',
                        ];
                    }
                }
            }
            return $result;
        }

        // Pure PHP streaming fallback
        $handle = fopen($manifest_path, 'r');
        if (!$handle) {
            return $result;
        }

        while (($line = fgets($handle)) !== false) {
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
                    'size'      => (int) filesize($full_path),
                    'mtime'     => gmdate('Y-m-d H:i:s', (int) filemtime($full_path)),
                ];
            }
        }
        fclose($handle);

        return $result;
    }

    /**
     * Check WordPress Core files against official WordPress.org checksums.
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
            // Skip non-PHP or localization files if needed
            $full_path = $wp_root . $rel;

            if (!file_exists($full_path)) {
                $result['files'][] = [
                    'path'      => 'web/wp/' . $rel,
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
                    'path'      => 'web/wp/' . $rel,
                    'component' => 'core',
                    'status'    => 'modified',
                    'size'      => (int) filesize($full_path),
                    'mtime'     => gmdate('Y-m-d H:i:s', (int) filemtime($full_path)),
                ];
            }
        }

        return $result;
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
            $data = self::simd_decode((string) file_get_contents($cache_file), true);
            if (is_array($data)) {
                return $data;
            }
        }

        $url = sprintf(
            'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
            rawurlencode($version),
            rawurlencode($locale)
        );

        $response = wp_remote_get($url, ['timeout' => 10]);
        if (is_wp_error($response) || 200 !== wp_remote_retrieve_response_code($response)) {
            return [];
        }

        $body = wp_remote_retrieve_body($response);
        $json = self::simd_decode($body, true);
        if (!is_array($json) || empty($json['checksums']) || !is_array($json['checksums'])) {
            return [];
        }

        $checksums = (array) $json['checksums'];
        file_put_contents($cache_file, self::simd_encode($checksums), LOCK_EX);

        return $checksums;
    }

    /**
     * Build or rebuild a local SHA256 baseline (fallback for environments without git manifests).
     *
     * @return int Count of hashed files.
     */
    public static function build_baseline(): int {
        $root = self::get_project_root();
        $hashes = [];

        $scan_dirs = [
            $root . '/web/app/mu-plugins',
            $root . '/web/app/plugins',
            $root . '/web/app/themes',
            $root . '/packages/plugins',
            $root . '/config',
        ];

        foreach ($scan_dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
            );

            foreach ($it as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $ext = strtolower($file->getExtension());
                if (!in_array($ext, ['php', 'js', 'css', 'json', 'yml', 'yaml'], true)) {
                    continue;
                }

                $full_path = $file->getPathname();
                $rel = str_replace($root . '/', '', $full_path);
                $hash = hash_file('sha256', $full_path);
                if (is_string($hash)) {
                    $hashes[$rel] = $hash;
                }
            }
        }

        $storage = self::get_storage_dir();
        file_put_contents(
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

        $data = self::simd_decode((string) file_get_contents($baseline_path), true);
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
                    'size'      => (int) filesize($full_path),
                    'mtime'     => gmdate('Y-m-d H:i:s', (int) filemtime($full_path)),
                ];
            }
        }

        return $result;
    }

    /**
     * Get file diff for a modified file against git HEAD or previous version.
     *
     * @param string $relative_path
     * @return array{success:bool,diff:string,info:string}
     */
    public static function get_file_diff(string $relative_path): array {
        $relative_path = ltrim($relative_path, '/');
        $root = self::get_project_root();
        $full_path = $root . '/' . $relative_path;

        if (!file_exists($full_path)) {
            return [
                'success' => false,
                'diff'    => 'File does not exist: ' . esc_html($relative_path),
                'info'    => 'Status: Missing',
            ];
        }

        // Try git diff if git repository is present
        if (self::command_exists('git') && is_dir($root . '/.git')) {
            $cmd = 'cd ' . escapeshellarg($root) . ' && git diff -- ' . escapeshellarg($relative_path) . ' 2>&1';
            $diff_output = shell_exec($cmd);
            if (is_string($diff_output) && '' !== trim($diff_output)) {
                return [
                    'success' => true,
                    'diff'    => $diff_output,
                    'info'    => 'Git working tree diff',
                ];
            }
        }

        // If file is in WP core, try comparing with official upstream
        if (str_starts_with($relative_path, 'web/wp/')) {
            global $wp_version;
            $core_sub = substr($relative_path, strlen('web/wp/'));
            $raw_url = 'https://raw.githubusercontent.com/WordPress/WordPress/' . ($wp_version ?: 'master') . '/' . $core_sub;
            $upstream = wp_remote_get($raw_url, ['timeout' => 5]);
            if (!is_wp_error($upstream) && 200 === wp_remote_retrieve_response_code($upstream)) {
                $orig_content = wp_remote_retrieve_body($upstream);
                $curr_content = (string) file_get_contents($full_path);
                $diff = self::compute_unified_diff($orig_content, $curr_content, "upstream/$core_sub", $relative_path);
                return [
                    'success' => true,
                    'diff'    => $diff,
                    'info'    => 'Diff against official WordPress ' . ($wp_version ?: 'core'),
                ];
            }
        }

        // Fallback: file inspection info + preview
        $mtime = gmdate('Y-m-d H:i:s', (int) filemtime($full_path));
        $size  = filesize($full_path);
        $perms = substr(sprintf('%o', fileperms($full_path)), -4);
        $sha   = hash_file('sha256', $full_path);

        $preview = (string) file_get_contents($full_path);
        if (strlen($preview) > 50000) {
            $preview = substr($preview, 0, 50000) . "\n\n... [File truncated at 50KB] ...";
        }

        return [
            'success' => true,
            'diff'    => $preview,
            'info'    => sprintf('Modified: %s | Size: %d bytes | Perms: %s | SHA256: %s', $mtime, $size, $perms, $sha),
        ];
    }

    /**
     * Read recent events from the real-time event log (inotifywait / auditd output).
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

        $lines = [];
        $fp = fopen($log_file, 'r');
        if (!$fp) {
            return [];
        }

        // Read last lines using fseek or streaming buffer
        $pos = -2;
        $text = [];
        fseek($fp, 0, SEEK_END);
        $file_size = ftell($fp);

        $buffer_size = 4096;
        $data = '';
        while ($file_size > 0 && count($lines) <= $limit) {
            $read_size = min($buffer_size, $file_size);
            $file_size -= $read_size;
            fseek($fp, $file_size);
            $chunk = fread($fp, $read_size);
            $data = $chunk . $data;
            $split = explode("\n", $data);
            if (count($split) > $limit + 1) {
                break;
            }
        }
        fclose($fp);

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
     * Generate clear copy-paste Red Hat Enterprise Linux / Linux server setup instructions.
     *
     * @return array<string,string>
     */
    public static function get_server_instructions(): array {
        $root = self::get_project_root();
        $web_dir = $root . '/web';

        $auditd_cmd = "sudo auditctl -w " . escapeshellarg($web_dir) . " -p wa -k gratis_fim\n"
            . "echo \"-w " . $web_dir . " -p wa -k gratis_fim\" | sudo tee /etc/audit/rules.d/gratis-fim.rules\n"
            . "sudo systemctl restart auditd";

        $service_content = "[Unit]\n"
            . "Description=Gratis Security File Integrity Monitor\n"
            . "After=network.target\n\n"
            . "[Service]\n"
            . "Type=simple\n"
            . "User=root\n"
            . "ExecStart=/usr/bin/inotifywait -m -r -e close_write,moved_to,create,delete \\\n"
            . "    --format '{\"time\":\"%T\",\"event\":\"%e\",\"file\":\"%w%f\"}' \\\n"
            . "    --exclude '/(uploads|cache|\\.git)/' \\\n"
            . "    " . escapeshellarg($web_dir) . "\n"
            . "StandardOutput=append:/var/log/gratis-fim.jsonl\n"
            . "Restart=always\n\n"
            . "[Install]\n"
            . "WantedBy=multi-user.target\n";

        $inotify_setup = "sudo tee /etc/systemd/system/gratis-fim.service << 'EOF'\n"
            . $service_content
            . "EOF\n\n"
            . "sudo systemctl daemon-reload\n"
            . "sudo systemctl enable --now gratis-fim\n"
            . "sudo chmod 644 /var/log/gratis-fim.jsonl";

        $aide_setup = "sudo dnf install -y aide\n"
            . "sudo aide --init\n"
            . "sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz\n"
            . "sudo aide --check";

        $wpcli_cmd = "wp gratis-security fim scan\n"
            . "wp gratis-security fim status\n"
            . "wp gratis-security fim diff <file-path>";

        return [
            'auditd'  => $auditd_cmd,
            'inotify' => $inotify_setup,
            'aide'    => $aide_setup,
            'wpcli'   => $wpcli_cmd,
            'service' => $service_content,
        ];
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
        if (str_contains($path, 'vendor/')) {
            return 'vendor';
        }
        if (str_contains($path, 'config/')) {
            return 'config';
        }
        return 'other';
    }

    /**
     * Get root directory of project.
     */
    public static function get_project_root(): string {
        if (defined('WP_CONTENT_DIR')) {
            $parent = dirname(WP_CONTENT_DIR);
            if (file_exists($parent . '/SOURCE-MANIFEST.sha256') || file_exists($parent . '/composer.json')) {
                return $parent;
            }
            $grand = dirname($parent);
            if (file_exists($grand . '/SOURCE-MANIFEST.sha256') || file_exists($grand . '/composer.json')) {
                return $grand;
            }
        }
        return rtrim(ABSPATH, '/');
    }

    /**
     * Helper to check if a command exists in the shell path.
     */
    private static function command_exists(string $cmd): bool {
        if (!function_exists('exec') || !function_exists('shell_exec')) {
            return false;
        }
        $whereIsCommand = (PHP_OS === 'WINNT') ? 'where' : 'which';
        $output = shell_exec("$whereIsCommand " . escapeshellarg($cmd) . ' 2>/dev/null');
        return is_string($output) && '' !== trim($output);
    }

    /**
     * Compute a simple unified diff between two strings.
     */
    private static function compute_unified_diff(string $from, string $to, string $from_name, string $to_name): string {
        $from_lines = explode("\n", str_replace("\r\n", "\n", $from));
        $to_lines   = explode("\n", str_replace("\r\n", "\n", $to));

        $diff = "--- " . $from_name . "\n+++ " . $to_name . "\n";
        $from_count = count($from_lines);
        $to_count   = count($to_lines);
        $max = max($from_count, $to_count);

        $hunk = [];
        for ($i = 0; $i < $max; $i++) {
            $f = $from_lines[$i] ?? null;
            $t = $to_lines[$i] ?? null;

            if ($f !== $t) {
                if (null !== $f) {
                    $hunk[] = "- " . $f;
                }
                if (null !== $t) {
                    $hunk[] = "+ " . $t;
                }
            }
        }

        if (empty($hunk)) {
            return "No line changes detected (whitespace or binary difference).";
        }

        return $diff . implode("\n", array_slice($hunk, 0, 500));
    }
}
