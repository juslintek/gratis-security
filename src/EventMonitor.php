<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Incremental log trailing, suspicious event evaluation, and persistent JSONL detection storage.
 */
final class EventMonitor {

    public const EVENTS_FILE = 'fim-events.jsonl';
    public const DETECTIONS_FILE = 'fim-detections.jsonl';
    public const STATE_FILE = 'fim-trail-state.json';
    public const CRON_HOOK = 'gratis_security_fim_trail_cron';
    public const MAX_DETECTIONS = 2000;
    public const MAX_BYTES_PER_TRAIL = 2097152;
    public const DEDUP_WINDOW_SECONDS = 60;

    /**
     * Discover ordered, deduplicated event log sources.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function discover_log_sources(?string $override_storage_dir = null): array {
        $candidates = [];

        $unit_path = '/etc/systemd/system/gratis-fim.service';
        if (@is_readable($unit_path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $unit_raw = (string) @file_get_contents($unit_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
            $parsed   = ServerInspector::analyze_systemd_unit($unit_raw, '');
            if (!empty($parsed['log_path'])) {
                $candidates[] = ['path' => (string) $parsed['log_path'], 'type' => 'inotify'];
            }
        }

        $storage_dir = $override_storage_dir ?? FileIntegrity::get_storage_dir();
        if ('' !== $storage_dir) {
            $norm_storage = rtrim(str_replace('\\', '/', $storage_dir), '/');
            $candidates[] = ['path' => $norm_storage . '/' . self::EVENTS_FILE, 'type' => 'inotify'];
            if (1 === preg_match('#^(.*)/sites/\d+/gratis-security/?$#', $norm_storage, $site_m)) {
                $candidates[] = ['path' => rtrim($site_m[1], '/') . '/gratis-security/' . self::EVENTS_FILE, 'type' => 'inotify'];
            }
        }

        $candidates[] = ['path' => FileIntegrity::EVENTS_LOG_DEFAULT, 'type' => 'inotify'];

        $root_dir = FileIntegrity::get_project_root();
        $candidates[] = ['path' => dirname($root_dir, 2) . '/shared/gratis-fim.jsonl', 'type' => 'inotify'];

        $audit_log = '/var/log/audit/audit.log';
        if (@is_readable($audit_log)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $candidates[] = ['path' => $audit_log, 'type' => 'auditd'];
        }

        $seen    = [];
        $sources = [];
        foreach ($candidates as $cand) {
            $path = (string) $cand['path'];
            if ('' === $path) {
                continue;
            }
            $norm = str_replace('\\', '/', $path);
            if (isset($seen[$norm])) {
                continue;
            }
            $seen[$norm] = true;

            $exists   = @file_exists($path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $readable = $exists && @is_readable($path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $sources[] = [
                'path'     => $path,
                'type'     => (string) $cand['type'],
                'exists'   => $exists,
                'readable' => $readable,
                'size'     => $exists ? (int) @filesize($path) : 0, // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                'mtime'    => $exists ? (int) @filemtime($path) : 0, // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            ];
        }

        return $sources;
    }

    /**
     * Normalize a single inotify JSONL or auditd log line.
     *
     * @return array<string,mixed>|null
     */
    public static function parse_log_line(string $raw, string $source_type = 'inotify', ?string $project_root = null): ?array {
        $raw = trim($raw);
        if ('' === $raw) {
            return null;
        }

        if ('auditd' === $source_type) {
            $web_dir  = ServerInspector::get_web_dir();
            $has_key  = str_contains($raw, 'gratis_fim');
            $has_path = str_contains($raw, 'type=PATH') && (
                ('' !== $web_dir && str_contains($raw, $web_dir))
                || (null !== $project_root && '' !== $project_root && str_contains($raw, $project_root))
            );
            if (!$has_key && !$has_path) {
                return null;
            }

            if (1 !== preg_match('/\bname="([^"]+)"/', $raw, $name_match)) {
                return null;
            }
            $raw_path = $name_match[1];
            $ts       = time();
            if (1 === preg_match('/msg=audit\((\d+)(?:\.\d+)?:\d+\)/', $raw, $ts_match)) {
                $ts = (int) $ts_match[1];
            }
            $time_str = gmdate('c', $ts);
            $rel_path = self::normalize_path($raw_path, $project_root);

            return [
                'time'      => $time_str,
                'timestamp' => $ts,
                'event'     => 'AUDIT_WRITE',
                'raw_path'  => $raw_path,
                'path'      => $rel_path,
                'component' => FileIntegrity::categorize_path($rel_path),
                'source'    => 'auditd',
                'raw'       => $raw,
            ];
        }

        $decoded = FileIntegrity::simd_decode($raw, true);
        if (!is_array($decoded)) {
            return null;
        }

        $raw_path = (string) ($decoded['file'] ?? $decoded['path'] ?? '');
        if ('' === $raw_path) {
            return null;
        }

        $time_str = trim((string) ($decoded['time'] ?? ''));
        $ts       = ('' !== $time_str) ? strtotime($time_str) : false;
        if (false === $ts) {
            $ts = time();
            if ('' === $time_str) {
                $time_str = gmdate('c', $ts);
            }
        }

        $event_name = strtoupper(trim((string) ($decoded['event'] ?? 'MODIFY')));
        if ('' === $event_name) {
            $event_name = 'MODIFY';
        }

        $rel_path = self::normalize_path($raw_path, $project_root);

        return [
            'time'      => $time_str,
            'timestamp' => $ts,
            'event'     => $event_name,
            'raw_path'  => $raw_path,
            'path'      => $rel_path,
            'component' => FileIntegrity::categorize_path($rel_path),
            'source'    => 'inotify',
            'raw'       => $raw,
        ];
    }

    /**
     * Check whether a relative path represents benign temporary or cache churn.
     */
    public static function is_ignored_path(string $rel_path): bool {
        $norm = str_replace('\\', '/', ltrim($rel_path, '/'));
        if ('' === $norm) {
            return true;
        }

        if (
            str_contains($norm, 'gratis-security/')
            || str_contains($norm, '/cache/')
            || str_starts_with($norm, 'web/app/cache/')
            || str_starts_with($norm, 'wp-content/cache/')
            || str_contains($norm, 'elementor/css/')
            || str_contains($norm, 'elementor/tmp/')
            || str_contains($norm, 'wp-rocket/')
            || str_contains($norm, 'litespeed/')
            || str_contains($norm, 'ewww/')
            || str_contains($norm, 'web/app/logs/')
            || str_contains($norm, 'wp-content/logs/')
            || str_contains($norm, 'vlt-cache-logs/')
            || str_contains($norm, 'vlt-traces/')
            || str_contains($norm, '/.git/')
            || str_starts_with($norm, '.git/')
        ) {
            return true;
        }

        return str_ends_with($norm, '.tmp')
            || str_ends_with($norm, '.swp')
            || str_ends_with($norm, '.swx')
            || str_ends_with($norm, '.js.map')
            || str_ends_with($norm, '.css.map')
            || str_ends_with($norm, '.log')
            || str_ends_with($norm, '~');
    }

    /**
     * Evaluate a normalized event against security rules.
     *
     * @param array<string,mixed>      $event
     * @param array<string,string>|null $manifest_hashes
     * @return array<string,mixed>|null
     */
    public static function evaluate_event(array $event, ?string $project_root = null, ?array $manifest_hashes = null): ?array {
        $rel_path = (string) ($event['path'] ?? '');
        if ('' === $rel_path || self::is_ignored_path($rel_path)) {
            return null;
        }

        $component   = (string) ($event['component'] ?? FileIntegrity::categorize_path($rel_path));
        $event_upper = strtoupper((string) ($event['event'] ?? ''));
        $is_write    = (1 === preg_match('/\b(CREATE|CLOSE_WRITE|MOVED_TO|MODIFY|AUDIT_WRITE|AUDIT)\b/', str_replace(',', ' ', $event_upper)));
        $full_path   = self::resolve_full_path($event, $project_root);

        // Rule 1: Executable or .htaccess written into uploads
        if (
            $is_write
            && ('uploads' === $component || str_contains($rel_path, 'uploads/'))
            && (1 === preg_match('/\.(php[0-9]?|phtml|phar|pht|shtml|cgi|sh)$/i', $rel_path) || '.htaccess' === basename($rel_path))
        ) {
            $patterns = self::scan_suspicious_code($full_path);
            $details  = 'Executable file written in uploads directory';
            if (!empty($patterns)) {
                $details .= ' (' . implode(', ', $patterns) . ')';
            }
            return self::make_detection($event, 'critical', 'executable_in_uploads', 'Executable file in uploads', $details);
        }

        // Rule 2: High-confidence webshell/backdoor signatures in code files
        if (
            $is_write
            && '' !== $full_path
            && 1 === preg_match('/\.(php[0-9]?|phtml|phar|inc|js)$/i', $rel_path)
        ) {
            $patterns = self::scan_suspicious_code($full_path);
            if (!empty($patterns)) {
                return self::make_detection(
                    $event,
                    'critical',
                    'suspicious_code_pattern',
                    'Suspicious code pattern detected',
                    'Matched signatures: ' . implode(', ', $patterns)
                );
            }
        }

        // Rule 3: Core or configuration files modified
        if (
            in_array($component, ['core', 'config'], true)
            || in_array(basename($rel_path), ['wp-config.php', '.env', '.htaccess', 'index.php', 'wp-cli.yml'], true)
        ) {
            return self::make_detection(
                $event,
                'high',
                'core_or_config_modified',
                'Core or config file modified',
                "Filesystem event {$event_upper} on protected {$component} file"
            );
        }

        // Rule 4: Manifest drift / untracked executable in plugins, mu-plugins, or themes
        if (!empty($manifest_hashes) && in_array($component, ['plugins', 'mu-plugins', 'themes'], true)) {
            $manifest_key = ltrim($rel_path, '/');
            if (isset($manifest_hashes[$manifest_key])) {
                if ('' !== $full_path && @is_file($full_path) && @is_readable($full_path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                    $actual_sha = @hash_file('sha256', $full_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                    if (is_string($actual_sha) && $actual_sha === $manifest_hashes[$manifest_key]) {
                        // File matches release manifest exactly; never fall through to runtime heuristics.
                        return null;
                    }
                    if (is_string($actual_sha) && $actual_sha !== $manifest_hashes[$manifest_key]) {
                        return self::make_detection(
                            $event,
                            'high',
                            'manifest_drift',
                            'Release manifest checksum mismatch',
                            'File SHA-256 differs from release manifest'
                        );
                    }
                } elseif (str_contains($event_upper, 'DELETE') && ('' === $full_path || !@file_exists($full_path))) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                    return self::make_detection(
                        $event,
                        'high',
                        'manifest_missing',
                        'Tracked manifest file deleted',
                        'File listed in release manifest was deleted'
                    );
                }
            } else {
                if (str_contains($event_upper, 'DELETE') && ('' === $full_path || !@file_exists($full_path))) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                    // Ephemeral/temp file outside manifest cleaned up.
                    return null;
                }
                if (
                    $is_write
                    && 1 === preg_match('/\.(php[0-9]?|phtml|phar|pht|shtml|cgi|sh)$/i', $rel_path)
                ) {
                    return self::make_detection(
                        $event,
                        'high',
                        'untracked_executable',
                        'Untracked executable outside manifest',
                        'New executable file outside release manifest'
                    );
                }
            }
        }

        // Rule 5: Runtime code modification in plugins/mu-plugins/themes
        if (
            in_array($component, ['plugins', 'mu-plugins', 'themes'], true)
            && 1 === preg_match('/\.(php[0-9]?|phtml|phar|js)$/i', $rel_path)
        ) {
            return self::make_detection(
                $event,
                'medium',
                'code_modified_runtime',
                'Runtime code modified',
                "Code file changed in {$component} ({$event_upper})"
            );
        }

        return null;
    }

    /**
     * Incrementally tail configured/discovered event logs from persisted offsets
     * and persist any new detections.
     *
     * @param array<int,string|array<string,mixed>>|null $sources
     * @return array<string,mixed>
     */
    public static function trail(?array $sources = null, ?string $storage_dir = null, ?string $project_root = null): array {
        $storage = $storage_dir ?? FileIntegrity::get_storage_dir();
        self::ensure_dir($storage);
        $root = $project_root ?? FileIntegrity::get_project_root();

        $source_list = self::normalize_sources($sources ?? self::discover_log_sources($storage));
        $manifest    = self::load_manifest_hashes($root);

        $lock_fp = @fopen($storage . '/fim-trail.lock', 'c+'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if ($lock_fp) {
            @flock($lock_fp, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        }

        try {
            $state = self::read_state_unlocked($storage);
            $existing_detections = self::read_all_detections_unlocked($storage);

            $dedup_map = [];
            foreach ($existing_detections as $det) {
                $key = ($det['rule'] ?? '') . '|' . ($det['path'] ?? '') . '|' . ($det['event'] ?? '');
                $ts  = (int) ($det['timestamp'] ?? 0);
                if (!isset($dedup_map[$key]) || $ts > $dedup_map[$key]) {
                    $dedup_map[$key] = $ts;
                }
            }

            $sources_checked = 0;
            $lines_read      = 0;
            $events_parsed   = 0;
            $new_detections  = [];

            foreach ($source_list as $src) {
                $path = (string) $src['path'];
                $type = (string) ($src['type'] ?? 'inotify');
                if ('' === $path || !@is_file($path) || !@is_readable($path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                    continue;
                }
                ++$sources_checked;

                @clearstatcache(true, $path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                $stat = @stat($path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                if (!is_array($stat)) {
                    continue;
                }

                $inode  = (int) ($stat['ino'] ?? 0);
                $size   = (int) ($stat['size'] ?? 0);
                $prev   = (array) ($state['sources'][$path] ?? []);
                $offset = (int) ($prev['offset'] ?? 0);

                // Reset cursor on log rotation or truncation
                if ($inode !== (int) ($prev['inode'] ?? 0) || $size < $offset) {
                    $offset = 0;
                }

                if ($size > $offset) {
                    $fp = @fopen($path, 'rb'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
                    if ($fp) {
                        @fseek($fp, $offset); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                        $to_read = min(self::MAX_BYTES_PER_TRAIL, $size - $offset);
                        $chunk   = ($to_read > 0) ? (string) @fread($fp, $to_read) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Low-level local filesystem/OS security operation.
                        @fclose($fp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Low-level local filesystem/OS security operation.

                        $last_nl = strrpos($chunk, "\n");
                        if (false !== $last_nl) {
                            $complete = substr($chunk, 0, $last_nl + 1);
                            $offset  += $last_nl + 1;

                            foreach (explode("\n", $complete) as $line) {
                                $trimmed = trim($line);
                                if ('' === $trimmed) {
                                    continue;
                                }
                                ++$lines_read;
                                $parsed = self::parse_log_line($trimmed, $type, $root);
                                if (null === $parsed) {
                                    continue;
                                }
                                ++$events_parsed;

                                $det = self::evaluate_event($parsed, $root, $manifest);
                                if (null === $det) {
                                    continue;
                                }

                                $dedup_key = $det['rule'] . '|' . $det['path'] . '|' . $det['event'];
                                if (isset($dedup_map[$dedup_key]) && abs($det['timestamp'] - $dedup_map[$dedup_key]) <= self::DEDUP_WINDOW_SECONDS) {
                                    continue;
                                }

                                $dedup_map[$dedup_key] = $det['timestamp'];
                                $new_detections[]      = $det;
                            }
                        } elseif ($to_read >= self::MAX_BYTES_PER_TRAIL) {
                            // Single line exceeds MAX_BYTES_PER_TRAIL; advance past chunk to avoid stalling
                            $offset += strlen($chunk);
                        }
                    }
                }

                $state['sources'][$path] = [
                    'type'            => $type,
                    'inode'           => $inode,
                    'size'            => $size,
                    'offset'          => $offset,
                    'last_trailed_at' => gmdate('c'),
                ];
            }

            if (!empty($new_detections)) {
                $combined = array_merge($existing_detections, $new_detections);
                if (count($combined) > self::MAX_DETECTIONS) {
                    $combined = array_slice($combined, -self::MAX_DETECTIONS);
                }
                self::write_all_detections_unlocked($storage, $combined);
            }

            self::write_state_unlocked($storage, $state);

            if ('cli' === PHP_SAPI) {
                ServerInspector::refresh_cli_probe($storage);
            }

            return [
                'trailed_at'      => gmdate('c'),
                'sources_checked' => $sources_checked,
                'lines_read'      => $lines_read,
                'events_parsed'   => $events_parsed,
                'new_detections'  => count($new_detections),
                'detections'      => $new_detections,
                'state'           => $state['sources'],
            ];
        } finally {
            if ($lock_fp) {
                @flock($lock_fp, LOCK_UN); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                @fclose($lock_fp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Low-level local filesystem/OS security operation.
            }
        }
    }

    /**
     * Tail recent raw events from readable sources and apply filters.
     *
     * @param array<string,mixed>                        $filters
     * @param array<int,string|array<string,mixed>>|null $sources
     * @return array<string,mixed>
     */
    public static function query_events(array $filters = [], ?array $sources = null, ?string $storage_dir = null, ?string $project_root = null): array {
        $storage     = $storage_dir ?? FileIntegrity::get_storage_dir();
        $root        = $project_root ?? FileIntegrity::get_project_root();
        $source_list = self::normalize_sources($sources ?? self::discover_log_sources($storage));

        $search          = strtolower(trim((string) ($filters['search'] ?? '')));
        $event_filter    = strtoupper(trim((string) ($filters['event'] ?? '')));
        $component       = strtolower(trim((string) ($filters['component'] ?? '')));
        $source_filter   = strtolower(trim((string) ($filters['source'] ?? '')));
        $since           = strtolower(trim((string) ($filters['since'] ?? 'all')));
        if ('ALL' === $event_filter) {
            $event_filter = '';
        }
        if ('all' === $component) {
            $component = '';
        }
        if ('all' === $source_filter) {
            $source_filter = '';
        }
        $only_suspicious = !empty($filters['only_suspicious']);
        $page            = isset($filters['page']) ? max(1, (int) $filters['page']) : 1;
        $per_page_raw    = isset($filters['per_page'])
            ? ((int) $filters['per_page'] > 0 ? (int) $filters['per_page'] : 20)
            : (isset($filters['limit']) ? (int) $filters['limit'] : 100);
        $per_page        = max(1, min(500, $per_page_raw));

        $cutoff_ts = match ($since) {
            '15m' => time() - 900,
            '1h'  => time() - 3600,
            '24h' => time() - 86400,
            '7d'  => time() - 604800,
            default => 0,
        };

        $manifest = $only_suspicious ? self::load_manifest_hashes($root) : null;
        $matched  = [];
        $used_sources = [];

        foreach ($source_list as $src) {
            $path = (string) $src['path'];
            $type = (string) ($src['type'] ?? 'inotify');
            if ('' !== $source_filter && $type !== $source_filter) {
                continue;
            }
            if ('' === $path || !@is_file($path) || !@is_readable($path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                continue;
            }
            $used_sources[] = $path;

            $lines = self::tail_file_lines($path, 1500, 524288);
            foreach ($lines as $line) {
                $parsed = self::parse_log_line($line, $type, $root);
                if (null === $parsed) {
                    continue;
                }
                if ($cutoff_ts > 0 && (int) $parsed['timestamp'] < $cutoff_ts) {
                    continue;
                }
                if ('' !== $event_filter && !str_contains((string) $parsed['event'], $event_filter)) {
                    continue;
                }
                if ('' !== $component && (string) $parsed['component'] !== $component) {
                    continue;
                }
                if ('' !== $search) {
                    $haystack = strtolower(
                        $parsed['path'] . ' ' . $parsed['raw_path'] . ' ' . $parsed['event'] . ' ' . $parsed['raw']
                    );
                    if (!str_contains($haystack, $search)) {
                        continue;
                    }
                }
                if ($only_suspicious) {
                    $preview = self::evaluate_event($parsed, $root, $manifest);
                    if (null === $preview) {
                        continue;
                    }
                    $parsed['detection_preview'] = $preview;
                }

                $matched[] = $parsed;
            }
        }

        usort($matched, static fn(array $a, array $b): int => ((int) $b['timestamp']) <=> ((int) $a['timestamp']));

        $total_filtered = count($matched);
        $total_pages    = $total_filtered > 0 ? (int) ceil($total_filtered / $per_page) : 1;
        $offset         = ($page - 1) * $per_page;

        return [
            'events'         => array_slice($matched, $offset, $per_page),
            'total_matched'  => $total_filtered,
            'total_filtered' => $total_filtered,
            'page'           => $page,
            'per_page'       => $per_page,
            'total_pages'    => $total_pages,
            'sources'        => $used_sources,
        ];
    }

    /**
     * Query persisted detections with counts and filters.
     *
     * @param array<string,mixed> $filters
     * @return array<string,mixed>
     */
    public static function query_detections(array $filters = [], ?string $storage_dir = null): array {
        $storage = $storage_dir ?? FileIntegrity::get_storage_dir();
        $all     = self::read_all_detections_unlocked($storage);

        $counts = [
            'open'         => 0,
            'acknowledged' => 0,
            'resolved'     => 0,
            'critical'     => 0,
            'high'         => 0,
            'medium'       => 0,
            'total'        => count($all),
        ];

        foreach ($all as $det) {
            $st  = (string) ($det['status'] ?? 'open');
            $sev = (string) ($det['severity'] ?? 'medium');
            if (isset($counts[$st])) {
                ++$counts[$st];
            }
            if (isset($counts[$sev])) {
                ++$counts[$sev];
            }
        }

        $parsed_filters = self::parse_detection_filters($filters);
        $page           = isset($filters['page']) ? max(1, (int) $filters['page']) : 1;
        $per_page_raw   = isset($filters['per_page'])
            ? ((int) $filters['per_page'] > 0 ? (int) $filters['per_page'] : 20)
            : (isset($filters['limit']) ? (int) $filters['limit'] : 100);
        $per_page       = max(1, min(500, $per_page_raw));

        $filtered = [];
        foreach (array_reverse($all) as $det) {
            if (!self::matches_detection_filters($det, $parsed_filters)) {
                continue;
            }
            $filtered[] = $det;
        }

        $total_filtered = count($filtered);
        $total_pages    = $total_filtered > 0 ? (int) ceil($total_filtered / $per_page) : 1;
        $offset         = ($page - 1) * $per_page;

        return [
            'detections'     => array_slice($filtered, $offset, $per_page),
            'counts'         => $counts,
            'total_filtered' => $total_filtered,
            'page'           => $page,
            'per_page'       => $per_page,
            'total_pages'    => $total_pages,
        ];
    }

    /**
     * Update a detection's workflow status.
     */
    public static function update_detection_status(string $id, string $status, ?string $storage_dir = null): bool {
        if (!in_array($status, ['open', 'acknowledged', 'resolved'], true)) {
            return false;
        }

        $storage = $storage_dir ?? FileIntegrity::get_storage_dir();
        self::ensure_dir($storage);

        $lock_fp = @fopen($storage . '/fim-trail.lock', 'c+'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if ($lock_fp) {
            @flock($lock_fp, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        }

        try {
            $all     = self::read_all_detections_unlocked($storage);
            $updated = false;
            foreach ($all as &$det) {
                if (($det['id'] ?? '') === $id) {
                    $det['status']     = $status;
                    $det['updated_at'] = gmdate('c');
                    $updated           = true;
                    break;
                }
            }
            unset($det);

            if ($updated) {
                self::write_all_detections_unlocked($storage, $all);
            }
            return $updated;
        } finally {
            if ($lock_fp) {
                @flock($lock_fp, LOCK_UN); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                @fclose($lock_fp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Low-level local filesystem/OS security operation.
            }
        }
    }

    /**
     * Remove detections matching a status filter (or 'all').
     */
    public static function clear_detections(string $status_filter = 'resolved', ?string $storage_dir = null): int {
        $storage = $storage_dir ?? FileIntegrity::get_storage_dir();
        self::ensure_dir($storage);

        $lock_fp = @fopen($storage . '/fim-trail.lock', 'c+'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if ($lock_fp) {
            @flock($lock_fp, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        }

        try {
            $all = self::read_all_detections_unlocked($storage);
            if ('all' === $status_filter) {
                $removed = count($all);
                self::write_all_detections_unlocked($storage, []);
                return $removed;
            }

            $kept    = [];
            $removed = 0;
            foreach ($all as $det) {
                if (($det['status'] ?? 'open') === $status_filter) {
                    ++$removed;
                } else {
                    $kept[] = $det;
                }
            }

            if ($removed > 0) {
                self::write_all_detections_unlocked($storage, $kept);
            }
            return $removed;
        } finally {
            if ($lock_fp) {
                @flock($lock_fp, LOCK_UN); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                @fclose($lock_fp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Low-level local filesystem/OS security operation.
            }
        }
    }

    /**
     * Bulk update status for all detections matching the provided filters under LOCK_EX.
     *
     * @param array<string,mixed> $filters
     */
    public static function bulk_update_status(array $filters, string $new_status, ?string $storage_dir = null): int {
        if (!in_array($new_status, ['open', 'acknowledged', 'resolved'], true)) {
            return 0;
        }

        $storage        = $storage_dir ?? FileIntegrity::get_storage_dir();
        $parsed_filters = self::parse_detection_filters($filters);
        self::ensure_dir($storage);

        $lock_fp = @fopen($storage . '/fim-trail.lock', 'c+'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if ($lock_fp) {
            @flock($lock_fp, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        }

        try {
            $all     = self::read_all_detections_unlocked($storage);
            $updated = 0;
            $now_iso = gmdate('c');

            foreach ($all as &$det) {
                if (!self::matches_detection_filters($det, $parsed_filters)) {
                    continue;
                }
                if (($det['status'] ?? 'open') !== $new_status) {
                    $det['status']     = $new_status;
                    $det['updated_at'] = $now_iso;
                    ++$updated;
                }
            }
            unset($det);

            if ($updated > 0) {
                self::write_all_detections_unlocked($storage, $all);
            }
            return $updated;
        } finally {
            if ($lock_fp) {
                @flock($lock_fp, LOCK_UN); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                @fclose($lock_fp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Low-level local filesystem/OS security operation.
            }
        }
    }

    /**
     * Purge stored detections that are now verified clean against ignored paths,
     * release manifest SHA-256 hashes, or cleaned-up untracked deleted temp files.
     *
     * @return array{removed:int,remaining:int}
     */
    public static function purge_verified_detections(?string $project_root = null, ?string $storage_dir = null): array {
        $root     = $project_root ?? FileIntegrity::get_project_root();
        $storage  = $storage_dir ?? FileIntegrity::get_storage_dir();
        $manifest = self::load_manifest_hashes($root);
        self::ensure_dir($storage);

        $lock_fp = @fopen($storage . '/fim-trail.lock', 'c+'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if ($lock_fp) {
            @flock($lock_fp, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        }

        try {
            $all     = self::read_all_detections_unlocked($storage);
            $kept    = [];
            $removed = 0;

            foreach ($all as $det) {
                $path = (string) ($det['path'] ?? '');
                $rule = (string) ($det['rule'] ?? '');
                $ev   = strtoupper((string) ($det['event'] ?? ''));
                $rel  = ltrim(str_replace('\\', '/', $path), '/');

                $drop = false;
                if (self::is_ignored_path($path)) {
                    $drop = true;
                } elseif (
                    in_array($rule, ['code_modified_runtime', 'manifest_drift'], true)
                    && is_array($manifest)
                    && '' !== $rel
                    && isset($manifest[$rel])
                ) {
                    $full = self::resolve_full_path($det, $root);
                    if ('' !== $full && @is_file($full) && @is_readable($full)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                        $actual_sha = @hash_file('sha256', $full); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                        if (is_string($actual_sha) && $actual_sha === $manifest[$rel]) {
                            $drop = true;
                        }
                    }
                } elseif ('code_modified_runtime' === $rule && str_contains($ev, 'DELETE')) {
                    $in_manifest = is_array($manifest) && '' !== $rel && isset($manifest[$rel]);
                    $full        = self::resolve_full_path($det, $root);
                    if (!$in_manifest && '' === $full) {
                        $drop = true;
                    }
                }

                if ($drop) {
                    ++$removed;
                } else {
                    $kept[] = $det;
                }
            }

            if ($removed > 0) {
                self::write_all_detections_unlocked($storage, $kept);
            }

            return [
                'removed'   => $removed,
                'remaining' => count($kept),
            ];
        } finally {
            if ($lock_fp) {
                @flock($lock_fp, LOCK_UN); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                @fclose($lock_fp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Low-level local filesystem/OS security operation.
            }
        }
    }

    /**
     * @param array<string,mixed> $filters
     * @return array{severity:string,status:string,component:string,search:string}
     */
    private static function parse_detection_filters(array $filters): array {
        $sev  = strtolower(trim((string) ($filters['severity'] ?? '')));
        $stat = strtolower(trim((string) ($filters['status'] ?? '')));
        $comp = strtolower(trim((string) ($filters['component'] ?? '')));
        $srch = strtolower(trim((string) ($filters['search'] ?? '')));

        return [
            'severity'  => 'all' === $sev ? '' : $sev,
            'status'    => 'all' === $stat ? '' : $stat,
            'component' => 'all' === $comp ? '' : $comp,
            'search'    => $srch,
        ];
    }

    /**
     * @param array<string,mixed>                                        $det
     * @param array{severity:string,status:string,component:string,search:string} $filters
     */
    private static function matches_detection_filters(array $det, array $filters): bool {
        if ('' !== $filters['severity'] && strtolower((string) ($det['severity'] ?? '')) !== $filters['severity']) {
            return false;
        }
        if ('' !== $filters['status'] && strtolower((string) ($det['status'] ?? '')) !== $filters['status']) {
            return false;
        }
        if ('' !== $filters['component'] && strtolower((string) ($det['component'] ?? '')) !== $filters['component']) {
            return false;
        }
        if ('' !== $filters['search']) {
            $hay = strtolower(
                ($det['path'] ?? '') . ' ' . ($det['rule'] ?? '') . ' ' . ($det['title'] ?? '') . ' ' . ($det['details'] ?? '')
            );
            if (!str_contains($hay, $filters['search'])) {
                return false;
            }
        }
        return true;
    }

    /**
     * Return decoded trail cursor state.
     *
     * @return array<string,mixed>
     */
    public static function get_trail_state(?string $storage_dir = null): array {
        $storage = $storage_dir ?? FileIntegrity::get_storage_dir();
        return self::read_state_unlocked($storage);
    }

    private static function normalize_path(string $raw_path, ?string $project_root = null): string {
        if (null === $project_root) {
            return FileIntegrity::normalize_rel_path($raw_path);
        }

        $norm_raw  = str_replace('\\', '/', $raw_path);
        $norm_root = rtrim(str_replace('\\', '/', $project_root), '/');
        if ('' !== $norm_root && str_starts_with($norm_raw, $norm_root . '/')) {
            return substr($norm_raw, strlen($norm_root . '/'));
        }

        return ltrim($norm_raw, '/');
    }

    /**
     * @param array<string,mixed> $event
     */
    private static function resolve_full_path(array $event, ?string $project_root = null): string {
        $raw_path = (string) ($event['raw_path'] ?? '');
        if ('' !== $raw_path && @is_file($raw_path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            return $raw_path;
        }
        $root = $project_root ?? FileIntegrity::get_project_root();
        $rel  = ltrim((string) ($event['path'] ?? ''), '/');
        if ('' !== $root && '' !== $rel) {
            $candidate = rtrim($root, '/') . '/' . $rel;
            if (@is_file($candidate)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                return $candidate;
            }
        }
        return '';
    }

    /**
     * @return array<int,string>
     */
    private static function scan_suspicious_code(string $full_path): array {
        if ('' === $full_path || !@is_file($full_path) || !@is_readable($full_path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            return [];
        }
        $size = (int) @filesize($full_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        if ($size <= 0 || $size > 524288) {
            return [];
        }
        $content = @file_get_contents($full_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
        if (!is_string($content) || '' === $content) {
            return [];
        }

        $signatures = [
            'eval(base64_decode' => '/eval\s*\(\s*base64_decode\s*\(/i',
            'eval(gzinflate'     => '/eval\s*\(\s*gzinflate\s*\(/i',
            'eval(str_rot13'     => '/eval\s*\(\s*str_rot13\s*\(/i',
            'assert(eval'        => '/assert\s*\(\s*eval\s*\(/i',
            'base64_decode($_'   => '/base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i',
            'preg_replace(/e)'   => '/preg_replace\s*\([^)]*\/[a-z]*e[a-z]*[\'"]\s*,[^)]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i',
            'shell_exec($_'      => '/shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i',
            'system($_'          => '/system\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i',
            'passthru($_'        => '/passthru\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i',
        ];

        $hits = [];
        foreach ($signatures as $label => $regex) {
            if (1 === @preg_match($regex, $content)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                $hits[] = $label;
            }
        }
        return $hits;
    }

    /**
     * @param array<string,mixed> $event
     * @return array<string,mixed>
     */
    private static function make_detection(array $event, string $severity, string $rule, string $title, string $details): array {
        $path = (string) ($event['path'] ?? '');
        $time = (string) ($event['time'] ?? '');
        $ev   = (string) ($event['event'] ?? '');

        return [
            'id'          => 'det_' . substr(hash('sha256', $rule . '|' . $path . '|' . $time . '|' . $ev), 0, 12),
            'detected_at' => gmdate('c'),
            'event_time'  => $time,
            'timestamp'   => (int) ($event['timestamp'] ?? time()),
            'source'      => (string) ($event['source'] ?? 'inotify'),
            'severity'    => $severity,
            'rule'        => $rule,
            'title'       => $title,
            'event'       => $ev,
            'path'        => $path,
            'raw_path'    => (string) ($event['raw_path'] ?? ''),
            'component'   => (string) ($event['component'] ?? FileIntegrity::categorize_path($path)),
            'details'     => $details,
            'status'      => 'open',
        ];
    }

    /**
     * @return array<string,string>|null
     */
    private static function load_manifest_hashes(string $root): ?array {
        $path = rtrim($root, '/') . '/SOURCE-MANIFEST.sha256';
        if (!@is_file($path) || !@is_readable($path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            return null;
        }
        $fp = @fopen($path, 'rb'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if (!$fp) {
            return null;
        }
        $hashes = [];
        for ($line = fgets($fp); false !== $line; $line = fgets($fp)) {
            $line = trim($line);
            if ('' === $line || !str_contains($line, '  ')) {
                continue;
            }
            [$sha, $rel] = explode('  ', $line, 2);
            $rel = ltrim(str_replace('\\', '/', trim($rel)), './');
            if ('' !== $sha && '' !== $rel) {
                $hashes[$rel] = strtolower(trim($sha));
            }
        }
        fclose($fp); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming file handle close for security logs/locks.
        return empty($hashes) ? null : $hashes;
    }

    /**
     * @param array<int,string|array<string,mixed>> $sources
     * @return array<int,array<string,mixed>>
     */
    private static function normalize_sources(array $sources): array {
        $out = [];
        foreach ($sources as $src) {
            if (is_string($src)) {
                $out[] = ['path' => $src, 'type' => 'inotify'];
            } elseif (is_array($src) && !empty($src['path'])) {
                $out[] = [
                    'path' => (string) $src['path'],
                    'type' => (string) ($src['type'] ?? 'inotify'),
                ];
            }
        }
        return $out;
    }

    /**
     * @return array<string,mixed>
     */
    private static function read_state_unlocked(string $storage): array {
        $path = rtrim($storage, '/') . '/' . self::STATE_FILE;
        if (!@is_file($path) || !@is_readable($path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            return ['sources' => []];
        }
        $raw = (string) @file_get_contents($path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
        $dec = FileIntegrity::simd_decode($raw, true);
        if (!is_array($dec) || !isset($dec['sources']) || !is_array($dec['sources'])) {
            return ['sources' => []];
        }
        return $dec;
    }

    /**
     * @param array<string,mixed> $state
     */
    private static function write_state_unlocked(string $storage, array $state): void {
        $path = rtrim($storage, '/') . '/' . self::STATE_FILE;
        self::atomic_write($path, FileIntegrity::simd_encode($state));
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private static function read_all_detections_unlocked(string $storage): array {
        $path = rtrim($storage, '/') . '/' . self::DETECTIONS_FILE;
        if (!@is_file($path) || !@is_readable($path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            return [];
        }
        $fp = @fopen($path, 'rb'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if (!$fp) {
            return [];
        }
        $items = [];
        for ($line = fgets($fp); false !== $line; $line = fgets($fp)) {
            $line = trim($line);
            if ('' === $line) {
                continue;
            }
            $dec = FileIntegrity::simd_decode($line, true);
            if (is_array($dec) && !empty($dec['id'])) {
                $items[] = $dec;
            }
        }
        fclose($fp); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming file handle close for security logs/locks.
        return $items;
    }

    /**
     * @param array<int,array<string,mixed>> $detections
     */
    private static function write_all_detections_unlocked(string $storage, array $detections): void {
        $path  = rtrim($storage, '/') . '/' . self::DETECTIONS_FILE;
        $lines = [];
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        foreach ($detections as $det) {
            $encoded = function_exists('wp_json_encode')
                ? wp_json_encode($det, $flags)
                : json_encode($det, $flags); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Fallback when executed outside WordPress runtime.
            if (is_string($encoded)) {
                $lines[] = $encoded;
            }
        }
        $payload = empty($lines) ? '' : (implode("\n", $lines) . "\n");
        self::atomic_write($path, $payload);
    }

    private static function atomic_write(string $target, string $content): void {
        $dir = dirname($target);
        self::ensure_dir($dir);
        $tmp = @tempnam($dir, 'gs_'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        if (false === $tmp) {
            @file_put_contents($target, $content, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
            return;
        }
        if (false !== @file_put_contents($tmp, $content)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
            @chmod($tmp, 0640); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Low-level local filesystem/OS security operation.
            if (!@rename($tmp, $target)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.rename_rename -- Low-level local filesystem/OS security operation.
                @unlink($tmp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink -- Low-level local filesystem/OS security operation.
                @file_put_contents($target, $content, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
            }
        } else {
            @unlink($tmp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink -- Low-level local filesystem/OS security operation.
        }
    }

    private static function ensure_dir(string $dir): void {
        if (!@is_dir($dir)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            if (function_exists('wp_mkdir_p')) {
                wp_mkdir_p($dir);
            } else {
                @mkdir($dir, 0755, true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Low-level local filesystem/OS security operation.
            }
        }
    }

    /**
     * Efficient reverse-seek tail reader returning lines in chronological order.
     *
     * @return array<int,string>
     */
    private static function tail_file_lines(string $path, int $max_lines, int $max_bytes): array {
        $fp = @fopen($path, 'rb'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Low-level local filesystem/OS security operation.
        if (!$fp) {
            return [];
        }
        @fseek($fp, 0, SEEK_END); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $file_size = (int) @ftell($fp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        if ($file_size <= 0) {
            fclose($fp); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming file handle close for security logs/locks.
            return [];
        }

        $read_len = min($file_size, $max_bytes);
        $start    = $file_size - $read_len;
        @fseek($fp, $start); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $data = (string) @fread($fp, $read_len); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Low-level local filesystem/OS security operation.
        fclose($fp); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming file handle close for security logs/locks.

        // Drop partial leading line when reading mid-file
        if ($start > 0) {
            $first_nl = strpos($data, "\n");
            if (false !== $first_nl) {
                $data = substr($data, $first_nl + 1);
            }
        }

        $lines = array_values(array_filter(array_map('trim', explode("\n", $data)), static fn(string $l): bool => '' !== $l));
        if (count($lines) > $max_lines) {
            $lines = array_slice($lines, -$max_lines);
        }
        return $lines;
    }
}
