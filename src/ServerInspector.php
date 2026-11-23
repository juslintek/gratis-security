<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Inspects host OS, runtime identity, monitoring binaries, systemd/auditd configuration,
 * and builds tailored setup recommendations.
 */
final class ServerInspector {

    public const PROBE_SNAPSHOT_FILE = 'server-probe.json';
    public const PROBE_MAX_AGE_SECONDS = 86400;

    /**
     * Detect PHP runtime user, group, SAPI, and SELinux state.
     *
     * @return array<string,mixed>
     */
    public static function detect_runtime(): array {
        $uid = function_exists('posix_geteuid') ? (int) posix_geteuid() : -1;
        $gid = function_exists('posix_getegid') ? (int) posix_getegid() : -1;

        $user = '';
        if ($uid >= 0 && function_exists('posix_getpwuid')) {
            $pw = @posix_getpwuid($uid); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            if (is_array($pw) && !empty($pw['name'])) {
                $user = (string) $pw['name'];
            }
        }
        if ('' === $user) {
            $current = @get_current_user(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $user = (is_string($current) && '' !== $current) ? $current : 'unknown';
        }

        $group = '';
        if ($gid >= 0 && function_exists('posix_getgrgid')) {
            $gr = @posix_getgrgid($gid); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            if (is_array($gr) && !empty($gr['name'])) {
                $group = (string) $gr['name'];
            }
        }
        if ('' === $group) {
            $group = $user;
        }

        $selinux = 'unknown';
        if (@is_readable('/sys/fs/selinux/enforce')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $enforce = trim((string) @file_get_contents('/sys/fs/selinux/enforce')); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
            if ('1' === $enforce) {
                $selinux = 'enforcing';
            } elseif ('0' === $enforce) {
                $selinux = 'permissive';
            }
        } elseif (FileIntegrity::is_shell_available()) {
            $out = @shell_exec('getenforce 2>/dev/null'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            if (is_string($out) && '' !== trim($out)) {
                $val = strtolower(trim($out));
                if (in_array($val, ['enforcing', 'permissive', 'disabled'], true)) {
                    $selinux = $val;
                }
            } elseif (PHP_OS_FAMILY === 'Linux' && !@is_dir('/sys/fs/selinux')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                $selinux = 'disabled';
            }
        } elseif (PHP_OS_FAMILY === 'Linux' && !@is_dir('/sys/fs/selinux')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $selinux = 'disabled';
        }

        return [
            'uid'         => $uid,
            'gid'         => $gid,
            'user'        => $user,
            'group'       => $group,
            'is_root'     => (0 === $uid),
            'sapi'        => PHP_SAPI,
            'php_version' => PHP_VERSION,
            'selinux'     => $selinux,
        ];
    }

    /**
     * Detect OS distribution, family, auditd architecture, and init system.
     *
     * @return array<string,mixed>
     */
    public static function detect_os(?string $os_release_content = null, ?string $php_os_family = null, ?string $machine = null): array {
        $os_family_raw = $php_os_family ?? PHP_OS_FAMILY;
        $machine_val   = $machine ?? php_uname('m');

        if (null === $os_release_content && @is_readable('/etc/os-release')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $raw = @file_get_contents('/etc/os-release'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
            if (is_string($raw)) {
                $os_release_content = $raw;
            }
        }

        $parsed = [];
        if (is_string($os_release_content) && '' !== trim($os_release_content)) {
            foreach (preg_split('/\r?\n/', $os_release_content) ?: [] as $line) {
                $line = trim($line);
                if ('' === $line || str_starts_with($line, '#') || !str_contains($line, '=')) {
                    continue;
                }
                [$key, $val] = explode('=', $line, 2);
                $key = trim($key);
                $val = trim($val);
                if ((str_starts_with($val, '"') && str_ends_with($val, '"')) || (str_starts_with($val, "'") && str_ends_with($val, "'"))) {
                    $val = substr($val, 1, -1);
                }
                $parsed[strtoupper($key)] = $val;
            }
        }

        $id = strtolower(trim((string) ($parsed['ID'] ?? '')));
        if ('' === $id) {
            $id = (0 === strcasecmp($os_family_raw, 'Darwin')) ? 'darwin' : 'unknown';
        }

        $id_like_raw = strtolower(trim((string) ($parsed['ID_LIKE'] ?? '')));
        $id_like     = '' !== $id_like_raw
            ? array_values(array_filter(preg_split('/\s+/', $id_like_raw) ?: [], static fn(string $v): bool => '' !== $v))
            : [];

        $version_id  = (string) ($parsed['VERSION_ID'] ?? '');
        $pretty_name = trim((string) ($parsed['PRETTY_NAME'] ?? ''));
        if ('' === $pretty_name) {
            $pretty_name = (0 === strcasecmp($os_family_raw, 'Darwin'))
                ? ('macOS ' . php_uname('r'))
                : (PHP_OS . ' ' . php_uname('r'));
        }

        $family = 'unknown';
        $tokens = array_merge([$id], $id_like);
        foreach ($tokens as $tok) {
            if (in_array($tok, ['rhel', 'centos', 'rocky', 'almalinux', 'fedora', 'ol', 'amzn'], true)) {
                $family = 'rhel';
                break;
            }
            if (in_array($tok, ['debian', 'ubuntu', 'linuxmint', 'pop'], true)) {
                $family = 'debian';
                break;
            }
            if ('alpine' === $tok) {
                $family = 'alpine';
                break;
            }
            if (in_array($tok, ['arch', 'manjaro'], true)) {
                $family = 'arch';
                break;
            }
            if (in_array($tok, ['sles', 'opensuse', 'suse'], true) || str_starts_with($tok, 'opensuse-')) {
                $family = 'suse';
                break;
            }
        }
        if ('unknown' === $family && (0 === strcasecmp($os_family_raw, 'Darwin') || 'darwin' === $id)) {
            $family = 'macos';
        }

        $audit_arch = (1 === preg_match('/^(i[3-6]86|arm(?!64)|armv)/i', $machine_val)) ? 'b32' : 'b64';

        $init_system = 'none';
        if ('macos' === $family) {
            $init_system = 'launchd';
        } elseif (@is_dir('/run/systemd/system')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $init_system = 'systemd';
        } elseif (@is_dir('/run/openrc')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $init_system = 'openrc';
        }

        return [
            'id'          => $id,
            'id_like'     => $id_like,
            'version_id'  => $version_id,
            'pretty_name' => $pretty_name,
            'family'      => $family,
            'machine'     => $machine_val,
            'audit_arch'  => $audit_arch,
            'kernel'      => php_uname('r'),
            'init_system' => $init_system,
        ];
    }

    /**
     * Detect available server monitoring and package-management binaries.
     *
     * @return array<string,mixed>
     */
    public static function detect_tools(bool $can_shell): array {
        $php_candidates = ['/usr/bin/php', '/usr/local/bin/php'];
        if ('cli' === PHP_SAPI && '' !== PHP_BINARY) {
            $php_candidates[] = PHP_BINARY;
        }

        $specs = [
            'auditctl'    => ['/usr/sbin/auditctl', '/sbin/auditctl'],
            'augenrules'  => ['/usr/sbin/augenrules', '/sbin/augenrules'],
            'ausearch'    => ['/usr/sbin/ausearch', '/sbin/ausearch'],
            'inotifywait' => ['/usr/bin/inotifywait', '/usr/local/bin/inotifywait'],
            'systemctl'   => ['/usr/bin/systemctl', '/bin/systemctl'],
            'wp'          => ['/usr/local/bin/wp', '/usr/bin/wp'],
            'aide'        => ['/usr/sbin/aide', '/usr/bin/aide'],
            'git'         => ['/usr/bin/git', '/usr/local/bin/git'],
            'php_cli'     => $php_candidates,
        ];

        $tools = [];
        foreach ($specs as $name => $paths) {
            $bin = ('php_cli' === $name) ? 'php' : $name;
            $tools[$name] = self::probe_binary($bin, $paths, $can_shell);
        }

        $pkg_specs = [
            'dnf'     => ['/usr/bin/dnf', '/bin/dnf'],
            'yum'     => ['/usr/bin/yum', '/bin/yum'],
            'apt-get' => ['/usr/bin/apt-get', '/bin/apt-get'],
            'apk'     => ['/sbin/apk', '/usr/bin/apk'],
            'pacman'  => ['/usr/bin/pacman', '/bin/pacman'],
            'zypper'  => ['/usr/bin/zypper', '/bin/zypper'],
            'brew'    => ['/opt/homebrew/bin/brew', '/usr/local/bin/brew'],
        ];

        $pkg_manager = ['name' => '', 'path' => ''];
        foreach ($pkg_specs as $pkg_name => $paths) {
            $found = self::probe_binary($pkg_name, $paths, $can_shell);
            if ($found['available']) {
                $pkg_manager = ['name' => $pkg_name, 'path' => $found['path']];
                break;
            }
        }
        $tools['pkg_manager'] = $pkg_manager;

        return $tools;
    }

    /**
     * Parse and validate a systemd gratis-fim.service unit file.
     *
     * @return array<string,mixed>
     */
    public static function analyze_systemd_unit(string $content, string $expected_web_dir): array {
        $unfolded = (string) preg_replace('/\\\\\r?\n[ \t]*/', ' ', $content);

        $user       = '';
        $group      = '';
        $exec_start = '';
        $std_out    = '';

        foreach (preg_split('/\r?\n/', $unfolded) ?: [] as $line) {
            $trimmed = trim($line);
            if ('' === $trimmed || str_starts_with($trimmed, '#') || str_starts_with($trimmed, ';') || str_starts_with($trimmed, '[')) {
                continue;
            }
            if (!str_contains($trimmed, '=')) {
                continue;
            }
            [$key, $val] = explode('=', $trimmed, 2);
            $key = trim($key);
            $val = trim($val);

            if ('User' === $key) {
                $user = $val;
            } elseif ('Group' === $key) {
                $group = $val;
            } elseif ('ExecStart' === $key) {
                $exec_start = $val;
            } elseif ('StandardOutput' === $key) {
                $std_out = $val;
            }
        }

        $log_path = '';
        if ('' !== $std_out && 1 === preg_match('/^(?:append|file):(.+)$/', $std_out, $m)) {
            $log_path = trim($m[1]);
        }

        $issues = [];
        if ('' !== $exec_start) {
            if (1 === preg_match('/(?<!%)%(?!%)/', $exec_start)) {
                $issues[] = 'Unescaped % specifier in ExecStart (systemd will fail with bad-setting)';
            }
            if ((str_contains($exec_start, '%%T') || str_contains($exec_start, '%T')) && !str_contains($exec_start, '--timefmt')) {
                $issues[] = 'Missing --timefmt required by %T in --format';
            }
            if (str_contains($exec_start, '--exclude') && 1 === preg_match('/(?<!\\\\)\\\\\./', $exec_start)) {
                $issues[] = 'Single backslash in --exclude (use \\\\.git for systemd)';
            }

            $real_web = @realpath($expected_web_dir); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $has_expected = str_contains($exec_start, $expected_web_dir)
                || (is_string($real_web) && '' !== $real_web && str_contains($exec_start, $real_web));
            if (!$has_expected) {
                $issues[] = "Watched path does not match current web directory ({$expected_web_dir})";
            }
        } else {
            $issues[] = 'Missing ExecStart directive in unit file';
        }

        return [
            'valid'      => empty($issues),
            'user'       => $user,
            'group'      => $group,
            'exec_start' => $exec_start,
            'log_path'   => $log_path,
            'issues'     => $issues,
        ];
    }

    /**
     * Parse and validate auditd rules from auditctl -l or /etc/audit/rules.d/gratis-fim.rules.
     *
     * @return array<string,mixed>
     */
    public static function analyze_audit_rules(string $rules_text, string $expected_web_dir): array {
        $real_web      = @realpath($expected_web_dir); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $matched_lines = [];

        foreach (preg_split('/\r?\n/', $rules_text) ?: [] as $raw_line) {
            $line = trim($raw_line);
            if ('' === $line || str_starts_with($line, '#')) {
                continue;
            }
            $matches_key  = str_contains($line, 'gratis_fim');
            $matches_dir  = str_contains($line, $expected_web_dir)
                || (is_string($real_web) && '' !== $real_web && str_contains($line, $real_web));

            if ($matches_key || $matches_dir) {
                $matched_lines[] = $line;
            }
        }

        $has_rule          = !empty($matched_lines);
        $is_legacy_watch   = false;
        $is_modern_syscall = false;
        $matches_path      = false;

        foreach ($matched_lines as $line) {
            if (1 === preg_match('/^\s*-w\s+/', $line)) {
                $is_legacy_watch = true;
            }
            if (
                1 === preg_match('/(?:^|\s)-a\s+/', $line)
                && (str_contains($line, 'dir=') || str_contains($line, 'path='))
                && str_contains($line, 'perm=')
            ) {
                $is_modern_syscall = true;
            }
            if (
                str_contains($line, $expected_web_dir)
                || (is_string($real_web) && '' !== $real_web && str_contains($line, $real_web))
            ) {
                $matches_path = true;
            }
        }

        $issues = [];
        if ($is_legacy_watch) {
            $issues[] = 'Legacy -w watch rule detected; migrate to modern -a always,exit -F dir=... -F perm=wa -F key=gratis_fim';
        }
        if ($has_rule && !$matches_path) {
            $issues[] = "Audit rule path does not match current web directory ({$expected_web_dir})";
        }

        return [
            'has_rule'          => $has_rule,
            'is_legacy_watch'   => $is_legacy_watch,
            'is_modern_syscall' => $is_modern_syscall,
            'matches_path'      => $matches_path,
            'matched_lines'     => $matched_lines,
            'issues'            => $issues,
        ];
    }

    /**
     * Detect running inotifywait processes without requiring shell if /proc is readable.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function detect_processes(string $expected_web_dir, bool $can_shell): array {
        $real_web  = @realpath($expected_web_dir); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $processes = [];

        if (@is_dir('/proc') && @is_readable('/proc')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $entries = @scandir('/proc'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            if (is_array($entries)) {
                foreach ($entries as $entry) {
                    if (!ctype_digit($entry)) {
                        continue;
                    }
                    $cmdline_path = "/proc/{$entry}/cmdline";
                    if (!@is_readable($cmdline_path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                        continue;
                    }
                    $raw_cmd = @file_get_contents($cmdline_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
                    if (!is_string($raw_cmd) || '' === $raw_cmd) {
                        continue;
                    }
                    $cmd = trim(str_replace("\0", ' ', $raw_cmd));
                    if (!str_contains($cmd, 'inotifywait')) {
                        continue;
                    }

                    $user = 'unknown';
                    $status_path = "/proc/{$entry}/status";
                    if (@is_readable($status_path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                        $status_raw = (string) @file_get_contents($status_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
                        if (1 === preg_match('/^Uid:\s*(\d+)/m', $status_raw, $m)) {
                            $uid = (int) $m[1];
                            if (function_exists('posix_getpwuid')) {
                                $pw = @posix_getpwuid($uid); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                                $user = (is_array($pw) && !empty($pw['name'])) ? (string) $pw['name'] : (string) $uid;
                            } else {
                                $user = (string) $uid;
                            }
                        }
                    }

                    $matches = str_contains($cmd, $expected_web_dir)
                        || (is_string($real_web) && '' !== $real_web && str_contains($cmd, $real_web));

                    $processes[] = [
                        'pid'             => (int) $entry,
                        'user'            => $user,
                        'cmd'             => $cmd,
                        'matches_web_dir' => $matches,
                    ];
                }
            }
        }

        if (empty($processes) && $can_shell) {
            $ps_out = @shell_exec('ps -eo pid=,user=,args= 2>/dev/null'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            if (is_string($ps_out) && '' !== trim($ps_out)) {
                foreach (preg_split('/\r?\n/', trim($ps_out)) ?: [] as $line) {
                    if (1 !== preg_match('/^\s*(\d+)\s+(\S+)\s+(.+)$/', $line, $m)) {
                        continue;
                    }
                    $cmd = trim($m[3]);
                    if (!str_contains($cmd, 'inotifywait')) {
                        continue;
                    }
                    if (str_contains($cmd, 'grep') || str_starts_with($cmd, 'sh -c ')) {
                        continue;
                    }
                    $matches = str_contains($cmd, $expected_web_dir)
                        || (is_string($real_web) && '' !== $real_web && str_contains($cmd, $real_web));

                    $processes[] = [
                        'pid'             => (int) $m[1],
                        'user'            => $m[2],
                        'cmd'             => $cmd,
                        'matches_web_dir' => $matches,
                    ];
                }
            }
        }

        return $processes;
    }

    /**
     * Resolve the active web root directory.
     */
    public static function get_web_dir(): string {
        if (@is_dir('/var/www/12fa/deploy/current/web')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            return '/var/www/12fa/deploy/current/web';
        }
        $root = FileIntegrity::get_project_root();
        return @is_dir($root . '/web') ? ($root . '/web') : $root; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
    }

    /**
     * Resolve the WordPress core directory used by WP-CLI --path.
     */
    public static function get_wp_path(string $web_dir): string {
        return @is_dir($web_dir . '/wp') ? ($web_dir . '/wp') : rtrim(ABSPATH, '/'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
    }

    /**
     * Check whether the web directory traverses a deployment symlink (up to 3 parent levels).
     *
     * @return array<string,mixed>
     */
    public static function is_symlink_deploy(string $web_dir): array {
        $cur = rtrim($web_dir, '/');
        for ($i = 0; $i < 3 && '' !== $cur && '/' !== $cur; $i++) {
            if (@is_link($cur)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                $resolved = @realpath($web_dir); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                if (!is_string($resolved) || '' === $resolved) {
                    $resolved = (string) @realpath($cur); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                }
                return [
                    'is_symlink'    => true,
                    'symlink_path'  => $cur,
                    'resolved_path' => $resolved,
                ];
            }
            $cur = dirname($cur);
        }

        $resolved = @realpath($web_dir); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        return [
            'is_symlink'    => false,
            'symlink_path'  => '',
            'resolved_path' => is_string($resolved) ? $resolved : $web_dir,
        ];
    }

    /**
     * Build distro-aware, least-privilege setup recommendations and wizard steps.
     *
     * @param array<string,mixed> $inspection
     * @return array<string,mixed>
     */
    public static function build_recommendations(array $inspection, string $service_user_mode = 'php'): array {
        $runtime      = (array) ($inspection['runtime'] ?? []);
        $os           = (array) ($inspection['os'] ?? []);
        $tools        = (array) ($inspection['tools'] ?? []);
        $paths        = (array) ($inspection['paths'] ?? []);
        $services     = (array) ($inspection['services'] ?? []);
        $cron_info    = (array) ($inspection['cron'] ?? []);

        $family       = (string) ($os['family'] ?? 'unknown');
        $init_system  = (string) ($os['init_system'] ?? 'none');
        $audit_arch   = (string) ($os['audit_arch'] ?? 'b64');
        $pkg_name     = (string) ($tools['pkg_manager']['name'] ?? '');
        $has_auditctl = !empty($tools['auditctl']['available']);
        $has_inotify  = !empty($tools['inotifywait']['available']);
        $has_pkg      = ('' !== $pkg_name);

        $web_dir      = (string) ($paths['web_dir'] ?? self::get_web_dir());
        $wp_path      = (string) ($paths['wp_path'] ?? self::get_wp_path($web_dir));
        $raw_storage  = (string) ($paths['storage_dir'] ?? FileIntegrity::get_storage_dir());
        $storage_dir  = self::resolve_network_storage_dir($raw_storage);
        $storage_real = @realpath($storage_dir); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        if (!is_string($storage_real) || '' === $storage_real) {
            $parent_real  = @realpath(dirname($storage_dir)); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $storage_real = (is_string($parent_real) && '' !== $parent_real)
                ? (rtrim($parent_real, '/') . '/' . basename($storage_dir))
                : $storage_dir;
        }
        $symlink_info = (array) ($paths['symlink_deploy'] ?? self::is_symlink_deploy($web_dir));

        $tier = 'autonomous_php';
        if ('macos' !== $family && 'systemd' === $init_system && ($has_auditctl || $has_pkg) && ($has_inotify || $has_pkg)) {
            $tier = 'kernel_and_realtime';
        } elseif ('macos' !== $family && $has_inotify) {
            $tier = 'realtime_only';
        }

        // Package installation for missing tools only
        $missing_inotify = !$has_inotify;
        $missing_audit   = !$has_auditctl;
        $install_cmd     = self::build_package_install_command($family, $pkg_name, $missing_inotify, $missing_audit);

        // Auditd rules command
        $auditd_lines = [];
        $kernel_analysis = (array) ($services['auditd']['kernel_rules_analysis'] ?? []);
        $file_analysis   = (array) ($services['auditd']['rules_file_analysis'] ?? []);
        $has_legacy_rule = !empty($kernel_analysis['is_legacy_watch']) || !empty($file_analysis['is_legacy_watch']);
        if ($has_legacy_rule) {
            $auditd_lines[] = 'sudo auditctl -W ' . escapeshellarg($web_dir) . ' -p wa -k gratis_fim';
        }
        $audit_rule     = "-a always,exit -F arch={$audit_arch} -F dir={$web_dir} -F perm=wa -F key=gratis_fim";
        $auditd_lines[] = 'echo ' . escapeshellarg($audit_rule) . ' | sudo tee /etc/audit/rules.d/gratis-fim.rules';
        $auditd_lines[] = 'sudo augenrules --load';
        $auditd_lines[] = 'sudo auditctl -l';
        $auditd_cmd     = implode("\n", $auditd_lines);

        // Systemd unit & setup
        $runtime_user  = (string) ($runtime['user'] ?? '');
        $runtime_group = (string) ($runtime['group'] ?? '');
        $use_php_user  = ('php' === $service_user_mode && '' !== $runtime_user && 'unknown' !== $runtime_user);
        $svc_user      = $use_php_user ? $runtime_user : 'root';
        $svc_group     = $use_php_user ? ('' !== $runtime_group ? $runtime_group : $runtime_user) : 'root';
        $log_path      = $use_php_user ? ($storage_real . '/' . EventMonitor::EVENTS_FILE) : FileIntegrity::EVENTS_LOG_DEFAULT;
        $inotify_bin   = !empty($tools['inotifywait']['path']) ? (string) $tools['inotifywait']['path'] : '/usr/bin/inotifywait';

        $unit_lines = [
            '[Unit]',
            'Description=Gratis Security File Integrity Monitor',
            'After=network.target',
            '',
            '[Service]',
            'Type=simple',
            "User={$svc_user}",
        ];
        if ($use_php_user) {
            $unit_lines[] = "Group={$svc_group}";
        }
        $unit_lines[] = "ExecStart={$inotify_bin} -m -r -e close_write,moved_to,create,delete \\";
        $unit_lines[] = "    --timefmt '%%Y-%%m-%%dT%%H:%%M:%%S%%z' \\";
        $unit_lines[] = "    --format '{\"time\":\"%%T\",\"event\":\"%%e\",\"file\":\"%%w%%f\"}' \\";
        $unit_lines[] = "    --exclude '/(uploads|cache|\\\\.git)/' \\";
        $unit_lines[] = '    ' . escapeshellarg($web_dir);
        $unit_lines[] = "StandardOutput=append:{$log_path}";
        $unit_lines[] = 'Restart=always';
        $unit_lines[] = 'RestartSec=3';
        $unit_lines[] = 'NoNewPrivileges=yes';
        $unit_lines[] = 'PrivateTmp=yes';

        if ($use_php_user) {
            $unit_lines[] = 'ProtectSystem=strict';
            $unit_lines[] = "ReadWritePaths={$storage_real}";
            $in_home = str_starts_with($web_dir, '/home/')
                || str_starts_with($web_dir, '/root/')
                || str_starts_with($storage_real, '/home/')
                || str_starts_with($storage_real, '/root/');
            if (!$in_home) {
                $unit_lines[] = 'ProtectHome=yes';
            }
        }

        $unit_lines[] = '';
        $unit_lines[] = '[Install]';
        $unit_lines[] = 'WantedBy=multi-user.target';
        $service_content = implode("\n", $unit_lines) . "\n";

        $log_setup = [
            'sudo touch ' . escapeshellarg($log_path),
        ];
        if ($use_php_user) {
            $log_setup[] = 'sudo chown ' . escapeshellarg("{$svc_user}:{$svc_group}") . ' ' . escapeshellarg($log_path);
            $log_setup[] = 'sudo chmod 0640 ' . escapeshellarg($log_path);
        } else {
            $log_setup[] = 'sudo chmod 644 ' . escapeshellarg($log_path);
        }

        $inotify_setup = "sudo tee /etc/systemd/system/gratis-fim.service << 'EOF'\n"
            . $service_content
            . "EOF\n\n"
            . implode("\n", $log_setup) . "\n"
            . "sudo systemctl daemon-reload\n"
            . "sudo systemctl enable gratis-fim\n"
            . "sudo systemctl restart gratis-fim\n"
            . 'sudo systemctl status gratis-fim';

        // Cron command (trail every 5 minutes)
        $wp_bin = !empty($tools['wp']['path']) ? (string) $tools['wp']['path'] : 'wp';
        $cron_user = ('' !== $runtime_user && 'unknown' !== $runtime_user) ? $runtime_user : 'root';
        $cron_line = sprintf(
            '*/5 * * * * %s %s --path=%s gratis-security fim trail >/dev/null 2>&1',
            $cron_user,
            $wp_bin,
            $wp_path
        );
        $cron_cmd = 'echo ' . escapeshellarg($cron_line) . " | sudo tee /etc/cron.d/gratis-security\n"
            . 'sudo chmod 644 /etc/cron.d/gratis-security';

        $deploy_hook = 'sudo augenrules --load && sudo systemctl restart gratis-fim';

        $aide_setup = self::build_aide_command($family, $pkg_name);

        $path_flag = ' --path=' . escapeshellarg($wp_path);
        $wpcli_cmd = "wp gratis-security fim wizard{$path_flag}\n"
            . "wp gratis-security fim trail{$path_flag}\n"
            . "wp gratis-security fim detections{$path_flag}\n"
            . "wp gratis-security fim scan{$path_flag}\n"
            . "wp gratis-security fim status{$path_flag}\n"
            . "wp gratis-security fim diff <file-path>{$path_flag}";

        $steps = self::build_wizard_steps(
            $inspection,
            $tier,
            $install_cmd,
            $auditd_cmd,
            $inotify_setup,
            $cron_cmd,
            $deploy_hook,
            $symlink_info,
            $cron_info
        );

        return [
            'tier'              => $tier,
            'service_user_mode' => $use_php_user ? 'php' : 'root',
            'log_path'          => $log_path,
            'install'           => $install_cmd,
            'auditd'            => $auditd_cmd,
            'inotify'           => $inotify_setup,
            'aide'              => $aide_setup,
            'wpcli'             => $wpcli_cmd,
            'service'           => $service_content,
            'cron'              => $cron_cmd,
            'deploy_hook'       => $deploy_hook,
            'steps'             => $steps,
        ];
    }

    /**
     * Resolve the canonical network-wide storage directory for multisite installations.
     */
    private static function resolve_network_storage_dir(?string $storage_dir = null): string {
        $dir = str_replace('\\', '/', $storage_dir ?? FileIntegrity::get_storage_dir());
        if (1 === preg_match('#^(.*)/sites/\d+/gratis-security/?$#', $dir, $matches)) {
            return rtrim($matches[1], '/') . '/gratis-security';
        }
        return rtrim($dir, '/');
    }

    private static function is_dbus_denied(string $output): bool {
        $lower = strtolower($output);
        foreach ([
            'permission denied',
            'failed to connect to bus',
            'access denied',
            'system has not been booted',
            'operation not permitted',
        ] as $needle) {
            if (str_contains($lower, $needle)) {
                return true;
            }
        }
        return false;
    }

    private static function atomic_write_file(string $target, string $content): void {
        $dir = dirname($target);
        if (!@is_dir($dir)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            if (function_exists('wp_mkdir_p')) {
                wp_mkdir_p($dir);
            } else {
                @mkdir($dir, 0755, true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Low-level local filesystem/OS security operation.
            }
        }
        if (!@is_dir($dir) || !@is_writable($dir)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Low-level local filesystem/OS security operation.
            return;
        }
        $tmp = @tempnam($dir, 'gs_probe_'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        if (false === $tmp) {
            @file_put_contents($target, $content, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
            return;
        }
        if (false !== @file_put_contents($tmp, $content, LOCK_EX)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
            @chmod($tmp, 0644); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Low-level local filesystem/OS security operation.
            if (!@rename($tmp, $target)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.rename_rename -- Low-level local filesystem/OS security operation.
                @unlink($tmp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink -- Low-level local filesystem/OS security operation.
                @file_put_contents($target, $content, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Low-level local filesystem/OS security operation.
            }
        } else {
            @unlink($tmp); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink -- Low-level local filesystem/OS security operation.
        }
    }

    /**
     * Persist a CLI-probed server snapshot atomically so PHP-FPM can verify systemd/auditd under SELinux httpd_t.
     *
     * @param array<string,mixed> $data
     */
    public static function save_probe_snapshot(array $data, ?string $storage_dir = null): void {
        $dir = rtrim(str_replace('\\', '/', $storage_dir ?? FileIntegrity::get_storage_dir()), '/');
        if ('' === $dir) {
            return;
        }

        $payload = [
            'probed_at'  => (string) ($data['probed_at'] ?? gmdate('c')),
            'timestamp'  => (int) ($data['timestamp'] ?? time()),
            'sapi'       => (string) ($data['sapi'] ?? PHP_SAPI),
            'auditd'     => (array) ($data['auditd'] ?? []),
            'gratis_fim' => (array) ($data['gratis_fim'] ?? []),
            'processes'  => (array) ($data['processes'] ?? []),
        ];
        $json = FileIntegrity::simd_encode($payload);

        self::atomic_write_file($dir . '/' . self::PROBE_SNAPSHOT_FILE, $json);

        if ('cli' === PHP_SAPI) {
            $network_dir = self::resolve_network_storage_dir($dir);
            if (
                $network_dir !== $dir
                && '' !== $network_dir
                && (@is_writable($network_dir) || (!@is_dir($network_dir) && @is_writable(dirname($network_dir)))) // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Low-level local filesystem/OS security operation.
            ) {
                self::atomic_write_file($network_dir . '/' . self::PROBE_SNAPSHOT_FILE, $json);
            }
        }
    }

    /**
     * Load the newest non-expired CLI probe snapshot from local or multisite network storage.
     *
     * @return array<string,mixed>|null
     */
    public static function load_probe_snapshot(?string $storage_dir = null): ?array {
        $dir         = rtrim(str_replace('\\', '/', $storage_dir ?? FileIntegrity::get_storage_dir()), '/');
        $network_dir = self::resolve_network_storage_dir($dir);

        $candidates = [];
        if ('' !== $dir) {
            $candidates[] = $dir . '/' . self::PROBE_SNAPSHOT_FILE;
        }
        if ('' !== $network_dir && $network_dir !== $dir) {
            $candidates[] = $network_dir . '/' . self::PROBE_SNAPSHOT_FILE;
        }

        $now  = time();
        $best = null;
        $best_ts = 0;

        foreach ($candidates as $path) {
            if (!@is_file($path) || !@is_readable($path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                continue;
            }
            $raw = @file_get_contents($path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
            if (!is_string($raw) || '' === trim($raw)) {
                continue;
            }
            $snap = FileIntegrity::simd_decode($raw, true);
            if (!is_array($snap)) {
                continue;
            }
            $ts = (int) ($snap['timestamp'] ?? 0);
            if ($ts <= 0 || ($now - $ts) > self::PROBE_MAX_AGE_SECONDS) {
                continue;
            }
            if (null === $best || $ts > $best_ts) {
                $best    = $snap;
                $best_ts = $ts;
            }
        }

        return $best;
    }

    /**
     * Refresh the CLI probe snapshot when executed from CLI (e.g. cron trail).
     */
    public static function refresh_cli_probe(?string $storage_dir = null): void {
        if ('cli' !== PHP_SAPI) {
            return;
        }
        $can_shell = FileIntegrity::is_shell_available();
        $runtime   = self::detect_runtime();
        $selinux   = (string) ($runtime['selinux'] ?? 'unknown');
        $tools     = self::detect_tools($can_shell);
        $web_dir   = self::get_web_dir();
        $processes = self::detect_processes($web_dir, $can_shell);
        $auditd    = self::inspect_auditd($tools, $web_dir, $can_shell, $selinux);
        $fim_svc   = self::inspect_gratis_fim_service($tools, $web_dir, $processes, $can_shell, $selinux);

        if (empty($auditd['dbus_denied']) || empty($fim_svc['dbus_denied'])) {
            self::save_probe_snapshot(
                [
                    'auditd'     => $auditd,
                    'gratis_fim' => $fim_svc,
                    'processes'  => $processes,
                ],
                $storage_dir
            );
        }
    }

    /**
     * Run a full live server inspection and attach recommendations.
     *
     * @return array<string,mixed>
     */
    public static function inspect(string $service_user_mode = 'php'): array {
        $can_shell = FileIntegrity::is_shell_available();
        $runtime   = self::detect_runtime();
        $os        = self::detect_os();
        $tools     = self::detect_tools($can_shell);

        $root_dir    = FileIntegrity::get_project_root();
        $web_dir     = self::get_web_dir();
        $wp_path     = self::get_wp_path($web_dir);
        $storage_dir = FileIntegrity::get_storage_dir();
        $symlink     = self::is_symlink_deploy($web_dir);

        $wp_cli_candidates = [
            $root_dir . '/wp-cli.yml',
            $web_dir . '/wp-cli.yml',
        ];
        $wp_cli_yml_path = $root_dir . '/wp-cli.yml';
        $wp_cli_yml_exists = false;
        foreach ($wp_cli_candidates as $cand) {
            if (@file_exists($cand)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                $wp_cli_yml_path = $cand;
                $wp_cli_yml_exists = true;
                break;
            }
        }

        $candidates = EventMonitor::discover_log_sources($storage_dir);
        $primary_log = [
            'path'       => '',
            'exists'     => false,
            'readable'   => false,
            'writable'   => false,
            'size'       => 0,
            'mtime'      => 0,
            'candidates' => $candidates,
        ];
        foreach ($candidates as $cand) {
            if ('inotify' === $cand['type'] && $cand['exists'] && $cand['readable']) {
                $primary_log['path']     = $cand['path'];
                $primary_log['exists']   = true;
                $primary_log['readable'] = true;
                $primary_log['writable'] = @is_writable($cand['path']); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Low-level local filesystem/OS security operation.
                $primary_log['size']     = $cand['size'];
                $primary_log['mtime']    = $cand['mtime'];
                break;
            }
        }
        if ('' === $primary_log['path'] && !empty($candidates)) {
            $first = $candidates[0];
            $primary_log['path']     = $first['path'];
            $primary_log['exists']   = $first['exists'];
            $primary_log['readable'] = $first['readable'];
            $primary_log['writable'] = $first['exists'] ? @is_writable($first['path']) : @is_writable(dirname($first['path'])); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Low-level local filesystem/OS security operation.
            $primary_log['size']     = $first['size'];
            $primary_log['mtime']    = $first['mtime'];
        }

        $wp_cli_yml = [
            'exists' => $wp_cli_yml_exists,
            'path'   => $wp_cli_yml_path,
        ];

        $selinux      = (string) ($runtime['selinux'] ?? 'unknown');
        $log_readable = !empty($primary_log['readable']);
        $snapshot     = ('cli' !== PHP_SAPI) ? self::load_probe_snapshot($storage_dir) : null;

        $processes = self::detect_processes($web_dir, $can_shell);
        $auditd    = self::inspect_auditd($tools, $web_dir, $can_shell, $selinux, $snapshot);
        $fim_svc   = self::inspect_gratis_fim_service($tools, $web_dir, $processes, $can_shell, $selinux, $snapshot, $log_readable);
        if (empty($processes) && !empty($fim_svc['verified_via_probe']) && is_array($snapshot) && !empty($snapshot['processes']) && is_array($snapshot['processes'])) {
            $processes = $snapshot['processes'];
        }
        $manifests = self::inspect_manifests($root_dir, $tools, $can_shell);
        $cron      = self::inspect_cron($can_shell);

        if ('cli' === PHP_SAPI && (empty($auditd['dbus_denied']) || empty($fim_svc['dbus_denied']))) {
            self::save_probe_snapshot(
                [
                    'auditd'     => $auditd,
                    'gratis_fim' => $fim_svc,
                    'processes'  => $processes,
                ],
                $storage_dir
            );
        }

        $checks  = self::build_checks($os, $tools, $auditd, $fim_svc, $primary_log, $manifests, $cron, $wp_cli_yml);
        $summary = self::summarize_checks($checks);

        $result = [
            'checked_at' => gmdate('c'),
            'runtime'    => $runtime,
            'os'         => $os,
            'tools'      => $tools,
            'paths'      => [
                'project_root'   => $root_dir,
                'web_dir'        => $web_dir,
                'wp_path'        => $wp_path,
                'storage_dir'    => $storage_dir,
                'symlink_deploy' => $symlink,
                'wp_cli_yml'     => $wp_cli_yml,
                'event_log'      => $primary_log,
            ],
            'processes'  => $processes,
            'services'   => [
                'auditd'     => $auditd,
                'gratis_fim' => $fim_svc,
            ],
            'manifests'  => $manifests,
            'cron'       => $cron,
            'checks'     => $checks,
            'summary'    => $summary,
        ];

        $result['recommendations'] = self::build_recommendations($result, $service_user_mode);

        return $result;
    }

    /**
     * @param array<int,string> $candidate_paths
     * @return array{available:bool,path:string}
     */
    private static function probe_binary(string $name, array $candidate_paths, bool $can_shell): array {
        foreach ($candidate_paths as $path) {
            if ('' !== $path && @is_executable($path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                return ['available' => true, 'path' => $path];
            }
        }
        if ($can_shell) {
            $which_cmd = (PHP_OS === 'WINNT') ? 'where' : 'which';
            $out = @shell_exec($which_cmd . ' ' . escapeshellarg($name) . ' 2>/dev/null'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            if (is_string($out) && '' !== trim($out)) {
                $first = trim((string) strtok(trim($out), "\n"));
                if ('' !== $first) {
                    return ['available' => true, 'path' => $first];
                }
            }
        }
        return ['available' => false, 'path' => ''];
    }

    /**
     * @param array<string,mixed>      $tools
     * @param array<string,mixed>|null $snapshot
     * @return array<string,mixed>
     */
    private static function inspect_auditd(array $tools, string $web_dir, bool $can_shell, string $selinux = 'unknown', ?array $snapshot = null): array {
        $installed   = !empty($tools['auditctl']['available']);
        $active      = false;
        $svc_state   = 'unknown';
        $dbus_denied = false;

        if ($can_shell && !empty($tools['systemctl']['available'])) {
            $out     = @shell_exec('systemctl is-active auditd 2>&1'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            $trimmed = is_string($out) ? trim($out) : '';
            if (self::is_dbus_denied($trimmed) || ('' === $trimmed && 'enforcing' === $selinux && 'cli' !== PHP_SAPI)) {
                $dbus_denied = true;
            } elseif ('' !== $trimmed) {
                $svc_state = $trimmed;
                $active    = ('active' === $svc_state);
            }
        }

        $rules_file = '/etc/audit/rules.d/gratis-fim.rules';
        $rules_file_readable = @is_readable($rules_file); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $rules_file_analysis = null;
        if ($rules_file_readable) {
            $content = (string) @file_get_contents($rules_file); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
            $rules_file_analysis = self::analyze_audit_rules($content, $web_dir);
        }

        $kernel_checked  = false;
        $kernel_analysis = null;
        if ($can_shell && $installed) {
            $auditctl_bin = (string) ($tools['auditctl']['path'] ?? 'auditctl');
            $out = @shell_exec(escapeshellarg($auditctl_bin) . ' -l 2>&1'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            if (is_string($out) && '' !== trim($out) && !str_contains(strtolower($out), 'must be root') && !self::is_dbus_denied($out)) {
                $kernel_checked  = true;
                $kernel_analysis = self::analyze_audit_rules($out, $web_dir);
            }
        }

        $used_snapshot = false;
        if ($dbus_denied && is_array($snapshot) && !empty($snapshot['auditd']) && is_array($snapshot['auditd'])) {
            $snap_audit = $snapshot['auditd'];
            if (empty($snap_audit['dbus_denied']) && ('unknown' !== ($snap_audit['service_state'] ?? 'unknown') || !empty($snap_audit['active']))) {
                $active    = !empty($snap_audit['active']);
                $svc_state = (string) ($snap_audit['service_state'] ?? 'unknown');
                if (!$kernel_checked && !empty($snap_audit['kernel_rules_checked'])) {
                    $kernel_checked  = true;
                    $kernel_analysis = is_array($snap_audit['kernel_rules_analysis'] ?? null) ? $snap_audit['kernel_rules_analysis'] : null;
                }
                if (!$rules_file_readable && !empty($snap_audit['rules_file_readable'])) {
                    $rules_file_readable = true;
                    $rules_file_analysis = is_array($snap_audit['rules_file_analysis'] ?? null) ? $snap_audit['rules_file_analysis'] : null;
                }
                $used_snapshot = true;
            }
        }

        $status  = 'missing';
        $summary = 'auditd is not installed';
        $active_analysis = $kernel_analysis ?? $rules_file_analysis;

        if ($installed && $dbus_denied && !$used_snapshot) {
            $status  = 'unverifiable';
            $summary = 'SELinux enforcing (httpd_t) blocks systemctl/auditctl in PHP-FPM; verify via CLI (wp gratis-security wizard) or cron';
        } elseif ($installed && $active) {
            if (is_array($active_analysis) && !empty($active_analysis['has_rule']) && empty($active_analysis['issues'])) {
                $status  = 'ok';
                $summary = 'auditd active with valid gratis_fim rule';
            } elseif (is_array($active_analysis) && !empty($active_analysis['has_rule'])) {
                $status  = 'warn';
                $summary = implode('; ', $active_analysis['issues']);
            } elseif (!$kernel_checked && !$rules_file_readable) {
                $status  = 'unverifiable';
                $summary = 'auditd is active, but rules cannot be read as non-root PHP user';
            } else {
                $status  = 'warn';
                $summary = 'auditd is active, but no gratis_fim rule was found';
            }
        } elseif ($installed) {
            $status  = 'warn';
            $summary = "auditd installed (service state: {$svc_state})";
        }

        if ($used_snapshot) {
            $summary .= ' (verified via CLI probe)';
        }

        return [
            'installed'             => $installed,
            'active'                => $active,
            'service_state'         => $svc_state,
            'rules_file'            => $rules_file,
            'rules_file_readable'   => $rules_file_readable,
            'rules_file_analysis'   => $rules_file_analysis,
            'kernel_rules_checked'  => $kernel_checked,
            'kernel_rules_analysis' => $kernel_analysis,
            'dbus_denied'           => $dbus_denied,
            'verified_via_probe'    => $used_snapshot,
            'status'                => $status,
            'summary'               => $summary,
        ];
    }

    /**
     * @param array<string,mixed>            $tools
     * @param array<int,array<string,mixed>> $processes
     * @param array<string,mixed>|null       $snapshot
     * @return array<string,mixed>
     */
    private static function inspect_gratis_fim_service(
        array $tools,
        string $web_dir,
        array $processes,
        bool $can_shell,
        string $selinux = 'unknown',
        ?array $snapshot = null,
        bool $log_readable = false
    ): array {
        $unit_path   = '/etc/systemd/system/gratis-fim.service';
        $unit_exists = @file_exists($unit_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $unit_analysis = null;
        $unit_user     = '';

        if ($unit_exists && @is_readable($unit_path)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $raw = (string) @file_get_contents($unit_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
            $unit_analysis = self::analyze_systemd_unit($raw, $web_dir);
            $unit_user     = (string) ($unit_analysis['user'] ?? '');
        }

        $load_state   = 'unknown';
        $active_state = 'unknown';
        $sub_state    = 'unknown';
        $main_pid     = 0;
        $dbus_denied  = false;

        if ($can_shell && !empty($tools['systemctl']['available'])) {
            $show    = @shell_exec('systemctl show gratis-fim.service --property=LoadState,ActiveState,SubState,MainPID,User --no-pager 2>&1'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            $trimmed = is_string($show) ? trim($show) : '';
            if (self::is_dbus_denied($trimmed) || ('' === $trimmed && 'enforcing' === $selinux && 'cli' !== PHP_SAPI)) {
                $dbus_denied = true;
            } elseif ('' !== $trimmed) {
                foreach (preg_split('/\r?\n/', $trimmed) ?: [] as $line) {
                    if (!str_contains($line, '=')) {
                        continue;
                    }
                    [$k, $v] = explode('=', $line, 2);
                    $v = trim($v);
                    if ('LoadState' === $k) {
                        $load_state = $v;
                        if ('loaded' === $v) {
                            $unit_exists = true;
                        }
                    } elseif ('ActiveState' === $k) {
                        $active_state = $v;
                    } elseif ('SubState' === $k) {
                        $sub_state = $v;
                    } elseif ('MainPID' === $k) {
                        $main_pid = (int) $v;
                    } elseif ('User' === $k && '' === $unit_user && '' !== $v) {
                        $unit_user = $v;
                    }
                }
            }
        }

        $used_snapshot = false;
        if ($dbus_denied && is_array($snapshot) && !empty($snapshot['gratis_fim']) && is_array($snapshot['gratis_fim'])) {
            $snap_fim = $snapshot['gratis_fim'];
            if (
                empty($snap_fim['dbus_denied'])
                && (
                    'unknown' !== ($snap_fim['load_state'] ?? 'unknown')
                    || 'unknown' !== ($snap_fim['active_state'] ?? 'unknown')
                    || !empty($snap_fim['process_running'])
                    || !empty($snapshot['processes'])
                )
            ) {
                $load_state   = (string) ($snap_fim['load_state'] ?? $load_state);
                $active_state = (string) ($snap_fim['active_state'] ?? $active_state);
                $sub_state    = (string) ($snap_fim['sub_state'] ?? $sub_state);
                $main_pid     = (int) ($snap_fim['main_pid'] ?? $main_pid);
                if (!empty($snap_fim['unit_exists'])) {
                    $unit_exists = true;
                }
                if ('' === $unit_user && !empty($snap_fim['unit_user'])) {
                    $unit_user = (string) $snap_fim['unit_user'];
                }
                if (null === $unit_analysis && is_array($snap_fim['unit_analysis'] ?? null)) {
                    $unit_analysis = $snap_fim['unit_analysis'];
                }
                if (empty($processes) && !empty($snapshot['processes']) && is_array($snapshot['processes'])) {
                    $processes = $snapshot['processes'];
                }
                $used_snapshot = true;
            }
        }

        $process_running = !empty($processes) || $main_pid > 0 || ($used_snapshot && !empty($snapshot['gratis_fim']['process_running']));
        $status  = 'missing';
        $summary = 'gratis-fim.service not configured';

        if ('active' === $active_state && 'running' === $sub_state) {
            if (is_array($unit_analysis) && !empty($unit_analysis['issues'])) {
                $status  = 'warn';
                $summary = 'Service active with unit warnings: ' . implode('; ', $unit_analysis['issues']);
            } else {
                $status  = 'ok';
                $summary = 'gratis-fim.service active (running)';
            }
        } elseif ($process_running) {
            $matching = array_filter($processes, static fn(array $p): bool => !empty($p['matches_web_dir']));
            $status   = !empty($matching) ? 'ok' : 'warn';
            $summary  = !empty($matching)
                ? 'inotifywait process running for web directory'
                : 'inotifywait process running, but watched path does not match web directory';
        } elseif ($dbus_denied && !$used_snapshot) {
            if ($unit_exists && is_array($unit_analysis) && !empty($unit_analysis['issues'])) {
                $status  = 'warn';
                $summary = 'Unit warnings: ' . implode('; ', $unit_analysis['issues']);
            } elseif ($unit_exists && is_array($unit_analysis) && empty($unit_analysis['issues']) && $log_readable) {
                $status  = 'ok';
                $summary = 'Unit valid and event log readable (systemd status hidden by SELinux httpd_t)';
            } elseif ($unit_exists) {
                $status  = 'unverifiable';
                $summary = 'Unit exists, but SELinux enforcing (httpd_t) blocks systemctl D-Bus in PHP-FPM';
            } else {
                $status  = 'unverifiable';
                $summary = 'SELinux enforcing (httpd_t) blocks systemctl D-Bus in PHP-FPM; verify via CLI (wp gratis-security wizard) or cron';
            }
        } elseif ($unit_exists || 'loaded' === $load_state) {
            $status  = 'warn';
            $summary = "Unit exists (state: {$active_state}/{$sub_state})";
            if (is_array($unit_analysis) && !empty($unit_analysis['issues'])) {
                $summary .= ' - ' . implode('; ', $unit_analysis['issues']);
            }
        }

        if ($used_snapshot) {
            $summary .= ' (verified via CLI probe)';
        }

        return [
            'unit_exists'        => $unit_exists,
            'unit_path'          => $unit_path,
            'unit_analysis'      => $unit_analysis,
            'load_state'         => $load_state,
            'active_state'       => $active_state,
            'sub_state'          => $sub_state,
            'main_pid'           => $main_pid,
            'unit_user'          => $unit_user,
            'process_running'    => $process_running,
            'dbus_denied'        => $dbus_denied,
            'verified_via_probe' => $used_snapshot,
            'status'             => $status,
            'summary'            => $summary,
        ];
    }

    /**
     * @param array<string,mixed> $tools
     * @return array<string,mixed>
     */
    private static function inspect_manifests(string $root_dir, array $tools, bool $can_shell): array {
        $source   = @file_exists($root_dir . '/SOURCE-MANIFEST.sha256') ? ($root_dir . '/SOURCE-MANIFEST.sha256') : null; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
        $composer = @file_exists($root_dir . '/COMPOSER-MANIFEST.sha256') ? ($root_dir . '/COMPOSER-MANIFEST.sha256') : null; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.

        $revision = null;
        if (@file_exists($root_dir . '/REVISION')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $rev_raw = trim((string) @file_get_contents($root_dir . '/REVISION')); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Low-level local filesystem/OS security operation.
            if ('' !== $rev_raw) {
                $revision = $rev_raw;
            }
        } elseif ($can_shell && !empty($tools['git']['available']) && @is_dir($root_dir . '/.git')) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
            $git_rev = @shell_exec('cd ' . escapeshellarg($root_dir) . ' && git rev-parse --short HEAD 2>/dev/null'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            if (is_string($git_rev) && '' !== trim($git_rev)) {
                $revision = trim($git_rev);
            }
        }

        $has_manifests = (null !== $source);
        $status        = $has_manifests ? 'ok' : 'warn';
        $summary       = $has_manifests
            ? 'SOURCE-MANIFEST.sha256 present' . (null !== $revision ? " (rev {$revision})" : '')
            : 'No release manifests found (using autonomous checksum/baseline mode)';

        return [
            'source_manifest'   => $source,
            'composer_manifest' => $composer,
            'revision'          => $revision,
            'has_manifests'     => $has_manifests,
            'status'            => $status,
            'summary'           => $summary,
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private static function inspect_cron(bool $can_shell): array {
        $wp_scan  = function_exists('wp_next_scheduled') && (false !== wp_next_scheduled(FileIntegrity::CRON_HOOK));
        $wp_trail = function_exists('wp_next_scheduled') && (false !== wp_next_scheduled(EventMonitor::CRON_HOOK));

        $sys_cron_found = false;
        $cron_paths = ['/etc/cron.d/gratis-security', '/etc/cron.d/gratis-fim'];
        foreach ($cron_paths as $cp) {
            if (@file_exists($cp)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level filesystem or OS probe under open_basedir/SELinux.
                $sys_cron_found = true;
                break;
            }
        }
        if (!$sys_cron_found && $can_shell) {
            $crontab = @shell_exec('crontab -l 2>/dev/null'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec,WordPress.PHP.NoSilencedErrors.Discouraged -- Low-level local filesystem/OS security operation.
            if (is_string($crontab) && str_contains($crontab, 'gratis-security')) {
                $sys_cron_found = true;
            }
        }

        $status  = ($wp_scan || $wp_trail || $sys_cron_found) ? 'ok' : 'warn';
        $parts   = [];
        if ($sys_cron_found) {
            $parts[] = 'system cron configured';
        }
        if ($wp_scan) {
            $parts[] = 'WP-Cron scan scheduled';
        }
        if ($wp_trail) {
            $parts[] = 'WP-Cron trail scheduled';
        }
        $summary = !empty($parts) ? implode(', ', $parts) : 'No scheduled FIM scan or trail cron detected';

        return [
            'wp_cron_scan'      => $wp_scan,
            'wp_cron_trail'     => $wp_trail,
            'system_cron_found' => $sys_cron_found,
            'status'            => $status,
            'summary'           => $summary,
        ];
    }

    /**
     * @param array<string,mixed> $os
     * @param array<string,mixed> $tools
     * @param array<string,mixed> $auditd
     * @param array<string,mixed> $fim_svc
     * @param array<string,mixed> $primary_log
     * @param array<string,mixed> $manifests
     * @param array<string,mixed> $cron
     * @param array{exists:bool,path:string} $wp_cli_yml
     * @return array<int,array<string,string>>
     */
    private static function build_checks(
        array $os,
        array $tools,
        array $auditd,
        array $fim_svc,
        array $primary_log,
        array $manifests,
        array $cron,
        array $wp_cli_yml = ['exists' => false, 'path' => '']
    ): array {
        $has_inotify  = !empty($tools['inotifywait']['available']);
        $has_auditctl = !empty($tools['auditctl']['available']);
        $tools_status = ($has_inotify && $has_auditctl)
            ? 'ok'
            : (($has_inotify || $has_auditctl) ? 'warn' : 'missing');
        $tools_detail = sprintf(
            '%s | inotifywait: %s | auditctl: %s',
            (string) ($os['pretty_name'] ?? 'Unknown OS'),
            $has_inotify ? 'yes' : 'no',
            $has_auditctl ? 'yes' : 'no'
        );

        $log_status = 'missing';
        $log_detail = 'No readable event log found';
        if (!empty($primary_log['exists']) && !empty($primary_log['readable'])) {
            $log_status = 'ok';
            $log_detail = "{$primary_log['path']} (" . (int) $primary_log['size'] . ' bytes)';
        } elseif (!empty($primary_log['exists'])) {
            $log_status = 'warn';
            $log_detail = "{$primary_log['path']} exists but is not readable by PHP";
        }

        $has_wp   = !empty($tools['wp']['available']);
        $has_yml  = !empty($wp_cli_yml['exists']);
        $yml_path = (string) ($wp_cli_yml['path'] ?? 'wp-cli.yml');
        if ($has_wp && $has_yml) {
            $wp_cli_status = 'ok';
            $wp_cli_detail = 'wp (' . (string) ($tools['wp']['path'] ?? 'wp') . ") + {$yml_path}";
        } elseif ($has_wp) {
            $wp_cli_status = 'warn';
            $wp_cli_detail = "wp installed, wp-cli.yml missing at {$yml_path} (use --path=...)";
        } else {
            $wp_cli_status = 'missing';
            $wp_cli_detail = 'wp CLI binary not installed';
        }

        return [
            [
                'id'     => 'os_tools',
                'label'  => 'OS & Monitoring Tools',
                'status' => $tools_status,
                'detail' => $tools_detail,
            ],
            [
                'id'     => 'auditd',
                'label'  => 'Kernel Audit (auditd)',
                'status' => (string) $auditd['status'],
                'detail' => (string) $auditd['summary'],
            ],
            [
                'id'     => 'gratis_fim',
                'label'  => 'Realtime Service (gratis-fim)',
                'status' => (string) $fim_svc['status'],
                'detail' => (string) $fim_svc['summary'],
            ],
            [
                'id'     => 'event_log',
                'label'  => 'Event Log (JSONL)',
                'status' => $log_status,
                'detail' => $log_detail,
            ],
            [
                'id'     => 'manifests',
                'label'  => 'Release Manifests',
                'status' => (string) $manifests['status'],
                'detail' => (string) $manifests['summary'],
            ],
            [
                'id'     => 'cron',
                'label'  => 'Scheduled Trail & Scan',
                'status' => (string) $cron['status'],
                'detail' => (string) $cron['summary'],
            ],
            [
                'id'     => 'wp_cli',
                'label'  => 'WP-CLI & wp-cli.yml',
                'status' => $wp_cli_status,
                'detail' => $wp_cli_detail,
            ],
        ];
    }

    /**
     * @param array<int,array<string,string>> $checks
     * @return array<string,mixed>
     */
    private static function summarize_checks(array $checks): array {
        $counts = [
            'passed'       => 0,
            'warn'         => 0,
            'missing'      => 0,
            'unverifiable' => 0,
            'total'        => count($checks),
        ];

        foreach ($checks as $check) {
            $st = $check['status'];
            if ('ok' === $st) {
                ++$counts['passed'];
            } elseif ('warn' === $st) {
                ++$counts['warn'];
            } elseif ('unverifiable' === $st) {
                ++$counts['unverifiable'];
            } else {
                ++$counts['missing'];
            }
        }

        $overall = 'ok';
        if ($counts['missing'] > 0) {
            $overall = 'needs_setup';
        } elseif ($counts['warn'] > 0 || $counts['unverifiable'] > 0) {
            $overall = 'warn';
        }
        $counts['overall'] = $overall;

        return $counts;
    }

    private static function build_package_install_command(string $family, string $pkg_name, bool $missing_inotify, bool $missing_audit): string {
        if (!$missing_inotify && !$missing_audit) {
            return '';
        }

        if ('rhel' === $family || 'dnf' === $pkg_name || 'yum' === $pkg_name) {
            $mgr = ('yum' === $pkg_name) ? 'yum' : 'dnf';
            $cmds = [];
            if ($missing_inotify) {
                $cmds[] = "sudo {$mgr} install -y epel-release && sudo {$mgr} install -y inotify-tools";
            }
            if ($missing_audit) {
                $cmds[] = "sudo {$mgr} install -y audit";
            }
            return implode("\n", $cmds);
        }

        if ('debian' === $family || 'apt-get' === $pkg_name) {
            $pkgs = [];
            if ($missing_inotify) {
                $pkgs[] = 'inotify-tools';
            }
            if ($missing_audit) {
                $pkgs[] = 'auditd';
            }
            return 'sudo apt-get update && sudo apt-get install -y ' . implode(' ', $pkgs);
        }

        if ('alpine' === $family || 'apk' === $pkg_name) {
            $pkgs = [];
            if ($missing_inotify) {
                $pkgs[] = 'inotify-tools';
            }
            if ($missing_audit) {
                $pkgs[] = 'audit';
            }
            return 'sudo apk add ' . implode(' ', $pkgs);
        }

        if ('arch' === $family || 'pacman' === $pkg_name) {
            $pkgs = [];
            if ($missing_inotify) {
                $pkgs[] = 'inotify-tools';
            }
            if ($missing_audit) {
                $pkgs[] = 'audit';
            }
            return 'sudo pacman -S --noconfirm ' . implode(' ', $pkgs);
        }

        if ('suse' === $family || 'zypper' === $pkg_name) {
            $pkgs = [];
            if ($missing_inotify) {
                $pkgs[] = 'inotify-tools';
            }
            if ($missing_audit) {
                $pkgs[] = 'audit';
            }
            return 'sudo zypper install -y ' . implode(' ', $pkgs);
        }

        return '';
    }

    private static function build_aide_command(string $family, string $pkg_name): string {
        $install = match (true) {
            'debian' === $family || 'apt-get' === $pkg_name => 'sudo apt-get install -y aide',
            'alpine' === $family || 'apk' === $pkg_name => 'sudo apk add aide',
            'arch' === $family || 'pacman' === $pkg_name => 'sudo pacman -S --noconfirm aide',
            'suse' === $family || 'zypper' === $pkg_name => 'sudo zypper install -y aide',
            'yum' === $pkg_name => 'sudo yum install -y aide',
            default => 'sudo dnf install -y aide',
        };

        return "{$install}\n"
            . "sudo aide --init\n"
            . "sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz\n"
            . 'sudo aide --check';
    }

    /**
     * @param array<string,mixed> $inspection
     * @param array<string,mixed> $symlink_info
     * @param array<string,mixed> $cron_info
     * @return array<int,array<string,string>>
     */
    private static function build_wizard_steps(
        array $inspection,
        string $tier,
        string $install_cmd,
        string $auditd_cmd,
        string $inotify_setup,
        string $cron_cmd,
        string $deploy_hook,
        array $symlink_info,
        array $cron_info
    ): array {
        $tools    = (array) ($inspection['tools'] ?? []);
        $services = (array) ($inspection['services'] ?? []);
        $paths    = (array) ($inspection['paths'] ?? []);

        $has_inotify  = !empty($tools['inotifywait']['available']);
        $has_auditctl = !empty($tools['auditctl']['available']);

        $steps = [];

        // Step 1: Packages
        $steps[] = [
            'id'      => 'install_packages',
            'title'   => 'Install monitoring packages',
            'status'  => ($has_inotify && $has_auditctl) ? 'done' : ('autonomous_php' === $tier ? 'optional' : 'action_needed'),
            'reason'  => ($has_inotify && $has_auditctl)
                ? 'inotifywait and auditctl are installed.'
                : ('autonomous_php' === $tier ? 'No Linux systemd/root tools available; autonomous PHP mode is active.' : 'Missing required server monitoring packages.'),
            'command' => $install_cmd,
            'note'    => 'Installs only missing packages for the detected distribution.',
        ];

        // Step 2: auditd
        $audit_status_raw = (string) ($services['auditd']['status'] ?? 'missing');
        $audit_step_status = match ($audit_status_raw) {
            'ok'           => 'done',
            'unverifiable' => 'manual_verify',
            default        => ('kernel_and_realtime' === $tier ? 'action_needed' : 'optional'),
        };
        $steps[] = [
            'id'      => 'configure_auditd',
            'title'   => 'Configure Linux auditd rules',
            'status'  => $audit_step_status,
            'reason'  => (string) ($services['auditd']['summary'] ?? 'Kernel audit watch rule for web directory.'),
            'command' => $auditd_cmd,
            'note'    => 'Uses modern -a always,exit syscall rule with detected architecture.',
        ];

        // Step 3: gratis-fim.service
        $fim_status_raw = (string) ($services['gratis_fim']['status'] ?? 'missing');
        $log_readable   = !empty($paths['event_log']['readable']);
        if ('ok' === $fim_status_raw && $log_readable) {
            $fim_step_status = 'done';
        } elseif ('unverifiable' === $fim_status_raw && 'autonomous_php' !== $tier) {
            $fim_step_status = 'manual_verify';
        } else {
            $fim_step_status = ('autonomous_php' === $tier ? 'optional' : 'action_needed');
        }
        $steps[] = [
            'id'      => 'configure_service',
            'title'   => 'Install gratis-fim systemd service',
            'status'  => $fim_step_status,
            'reason'  => (string) ($services['gratis_fim']['summary'] ?? 'Real-time inotifywait JSONL event logger.'),
            'command' => $inotify_setup,
            'note'    => 'Hardened unit with escaped systemd specifiers and pre-created log file.',
        ];

        // Step 4: Cron trail
        $cron_ok = !empty($cron_info['system_cron_found']) || !empty($cron_info['wp_cron_trail']);
        $steps[] = [
            'id'      => 'configure_cron',
            'title'   => 'Schedule incremental event trailing (cron)',
            'status'  => $cron_ok ? 'done' : 'action_needed',
            'reason'  => (string) ($cron_info['summary'] ?? 'Tails event logs every 5 minutes into persistent detections.'),
            'command' => $cron_cmd,
            'note'    => 'Runs WP-CLI fim trail without MySQL overhead.',
        ];

        // Step 5: Deploy hook (if symlink deploy)
        $is_sym = !empty($symlink_info['is_symlink']);
        $steps[] = [
            'id'      => 'deploy_hook',
            'title'   => 'Add post-deploy hook for symlink release switch',
            'status'  => $is_sym ? 'action_needed' : 'optional',
            'reason'  => $is_sym
                ? "Symlink deploy detected at {$symlink_info['symlink_path']} -> {$symlink_info['resolved_path']}."
                : 'No symlink deployment path detected.',
            'command' => $deploy_hook,
            'note'    => 'Reloads auditd and restarts inotifywait so watches follow the new release inode.',
        ];

        return $steps;
    }
}
