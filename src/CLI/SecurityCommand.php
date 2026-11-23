<?php declare(strict_types=1);
namespace Gratis\Security\CLI;

defined('ABSPATH') || exit;

use Gratis\Security\EventMonitor;
use Gratis\Security\FileIntegrity;
use Gratis\Security\MalwareScanner;
use Gratis\Security\RequestGuard;
use Gratis\Security\SecurityAudit;
use Gratis\Security\ServerInspector;
use Gratis\Security\SetupWizard;
use Gratis\Security\SignatureFeed;
use Gratis\Security\TwoFactor;

final class SecurityCommand {

    /**
     * Scan for malware.
     *
     * ## OPTIONS
     *
     * [--dir=<path>]
     * : Directory to scan (defaults to WP_CONTENT_DIR).
     *
     * [--deep]
     * : Scan all files without skipping manifest-verified core/plugin files.
     *
     * [--clamav]
     * : Also invoke local ClamAV (clamdscan/clamscan) if installed.
     *
     * [--format=<format>]
     * : Output format (table or json). Default: table.
     *
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args (unused).
     * @param array<string,string> $assoc_args Associative args.
     */
    // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP-CLI command signature.
    public function scan($args, $assoc_args): void {
        $dir    = isset($assoc_args['dir']) && '' !== (string) $assoc_args['dir'] ? (string) $assoc_args['dir'] : null;
        $deep   = isset($assoc_args['deep']);
        $clamav = isset($assoc_args['clamav']);
        $format = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';

        if ('json' !== $format) {
            $label_dir = $dir ?? (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : FileIntegrity::get_project_root());
            \WP_CLI::log("Scanning {$label_dir} for malware...");
        }

        $result = MalwareScanner::scan($dir, [
            'deep'       => $deep,
            'use_clamav' => $clamav,
        ]);

        if ('json' === $format) {
            \WP_CLI::line(self::encode_json($result));
            return;
        }

        $scanned = (int) ($result['scanned'] ?? 0);
        $skipped = (int) ($result['skipped_verified'] ?? 0);
        \WP_CLI::log("Files scanned: {$scanned} (skipped verified: {$skipped})");

        $findings = (array) ($result['findings'] ?? $result['suspicious'] ?? []);
        if (empty($findings)) {
            \WP_CLI::success('No suspicious files found.');
            return;
        }

        \WP_CLI::warning(count($findings) . ' suspicious file(s):');
        $rows = array_map(static fn(array $f): array => [
            'Path'     => (string) ($f['file'] ?? ''),
            'Severity' => strtoupper((string) ($f['severity'] ?? '')),
            'Category' => (string) ($f['category'] ?? ''),
            'Label'    => (string) ($f['label'] ?? $f['reason'] ?? ''),
            'Line'     => (string) ($f['line'] ?? '-'),
        ], $findings);
        \WP_CLI\Utils\format_items('table', $rows, ['Path', 'Severity', 'Category', 'Label', 'Line']);
    }

    /**
     * Show WAF block log.
     *
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args (unused).
     * @param array<string,string> $assoc_args Associative args (unused).
     */
    // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP-CLI command signature.
    public function blocks($args, $assoc_args): void {
        $log = \Gratis\Security\WAF::get_blocks(20);
        if (empty($log)) {
            \WP_CLI::log('No blocks recorded.');
            return;
        }
        $recent = array_reverse($log);
        $rows   = array_map(fn($e) => [
            'Time'   => $e['time'],
            'IP'     => $e['ip'],
            'Reason' => $e['reason'],
        ], $recent);
        \WP_CLI\Utils\format_items('table', $rows, ['Time', 'IP', 'Reason']);
    }

    /**
     * File Integrity & Monitoring commands.
     *
     * ## OPTIONS
     *
     * <subaction>
     * : One of: status, scan, diff, baseline, instructions, wizard, trail, detections, logs, purge-verified.
     *
     * [<file>]
     * : Relative file path for `diff`.
     *
     * [--check-vendor]
     * : Also verify COMPOSER-MANIFEST.sha256 during scan.
     *
     * [--user=<mode>]
     * : Service user mode for `wizard` (php or root).
     *
     * [--severity=<severity>]
     * : Filter `detections` by severity (critical, high, medium, all).
     *
     * [--status=<status>]
     * : Filter `detections` by status (open, acknowledged, resolved, all).
     *
     * [--component=<component>]
     * : Filter `detections` or `logs` by component.
     *
     * [--search=<term>]
     * : Filter `detections` or `logs` by substring.
     *
     * [--event=<event>]
     * : Filter `logs` by event name (CLOSE_WRITE, CREATE, DELETE, MOVED_TO, AUDIT_WRITE).
     *
     * [--source=<source>]
     * : Filter `logs` by source (inotify, auditd).
     *
     * [--since=<window>]
     * : Filter `logs` by time window (15m, 1h, 24h, 7d, all).
     *
     * [--suspicious]
     * : Only show suspicious events in `logs`.
     *
     * [--limit=<count>]
     * : Maximum rows for `detections` or `logs`.
     *
     * [--format=<format>]
     * : Output format (table or json).
     *
     * ## EXAMPLES
     *
     *     wp gratis-security fim status
     *     wp gratis-security fim scan
     *     wp gratis-security fim scan --check-vendor
     *     wp gratis-security fim diff web/app/mu-plugins/vlt-admin-menu.php
     *     wp gratis-security fim baseline
     *     wp gratis-security fim instructions
     *     wp gratis-security fim wizard --user=php
     *     wp gratis-security fim trail
     *     wp gratis-security fim detections --status=open
     *     wp gratis-security fim logs --since=1h --suspicious
     *     wp gratis-security fim purge-verified
     *
     * @subcommand fim
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args: subaction, [file].
     * @param array<string,string> $assoc_args Associative args.
     */
    public function fim($args, $assoc_args): void {
        $action = isset($args[0]) ? strtolower((string) $args[0]) : 'status';

        switch ($action) {
            case 'status':
                $caps = FileIntegrity::detect_server_capabilities();
                \WP_CLI::log('=== Gratis Security: Server & FIM Status ===');
                \WP_CLI::log("OS:                {$caps['os']}");
                \WP_CLI::log('SIMDJSON:          ' . ($caps['simdjson'] ? "Active (v{$caps['simdjson_version']})" : 'Not loaded'));
                \WP_CLI::log('Auditd:            ' . ($caps['auditd_active'] ? 'Active' : ($caps['auditctl'] ? 'Installed' : 'Missing')));
                \WP_CLI::log('Inotifywait:       ' . ($caps['inotifywait'] ? "Installed ({$caps['inotifywait_path']})" : 'Missing'));
                \WP_CLI::log('Release Manifest:  ' . ($caps['has_manifests'] ? "Found ({$caps['source_manifest']})" : 'Missing'));
                if (!empty($caps['revision'])) {
                    \WP_CLI::log("Release Revision:  {$caps['revision']}");
                }

                $report = FileIntegrity::get_last_report();
                if ($report) {
                    \WP_CLI::log('-------------------------------------------');
                    \WP_CLI::log("Last Scan:         {$report['scanned_at']}");
                    \WP_CLI::log("Engine:            {$report['engine']}");
                    \WP_CLI::log("Total Checked:     {$report['total_checked']}");
                    \WP_CLI::log("Modified Files:    {$report['modified_count']}");
                    \WP_CLI::log("Missing Files:     {$report['missing_count']}");
                    \WP_CLI::log("Untracked Files:   {$report['untracked_count']}");
                }
                break;

            case 'scan':
                $check_vendor = isset($assoc_args['check-vendor']);
                \WP_CLI::log('Running File Integrity Scan...');
                $start = microtime(true);
                $report = FileIntegrity::scan(['check_vendor' => $check_vendor]);
                $elapsed = round(microtime(true) - $start, 2);

                \WP_CLI::log("Checked {$report['total_checked']} files in {$elapsed}s using {$report['engine']} engine.");
                $total_changed = $report['modified_count'] + $report['missing_count'] + $report['untracked_count'];

                if (0 === $total_changed) {
                    \WP_CLI::success('All files match their versioned signatures perfectly!');
                    return;
                }

                \WP_CLI::warning("Found {$total_changed} changed file(s):");
                $rows = [];
                foreach ($report['files'] as $f) {
                    $rows[] = [
                        'Path'      => $f['path'],
                        'Component' => $f['component'],
                        'Status'    => strtoupper($f['status']),
                        'Size'      => isset($f['size']) && $f['size'] > 0 ? size_format((int) $f['size'], 1) : '-',
                        'Mtime'     => $f['mtime'] ?? '-',
                    ];
                }
                \WP_CLI\Utils\format_items('table', $rows, ['Path', 'Component', 'Status', 'Size', 'Mtime']);
                break;

            case 'diff':
                $file = isset($args[1]) ? (string) $args[1] : '';
                if ('' === $file) {
                    \WP_CLI::error('Please provide a relative file path: wp gratis-security fim diff <path>');
                    return;
                }
                $diff = FileIntegrity::get_file_diff($file);
                if (!$diff['success']) {
                    \WP_CLI::error($diff['diff']);
                    return;
                }
                \WP_CLI::log("=== Diff for: {$file} ===");
                \WP_CLI::log($diff['info']);
                \WP_CLI::log('-------------------------------------------');
                \WP_CLI::log($diff['diff']);
                break;

            case 'baseline':
                \WP_CLI::log('Rebuilding local baseline on disk...');
                $count = FileIntegrity::build_baseline();
                \WP_CLI::success("Saved local baseline with {$count} files into gratis-security storage (no MySQL).");
                break;

            case 'instructions':
                $instr = FileIntegrity::get_server_instructions();
                \WP_CLI::log("=== Red Hat / Linux Server Setup Instructions ===\n");
                \WP_CLI::log("1. Auditd (Kernel-level monitoring):\n" . $instr['auditd'] . "\n");
                \WP_CLI::log("2. Inotifywait (Real-time systemd service):\n" . $instr['inotify'] . "\n");
                break;

            case 'wizard':
                $mode   = (isset($assoc_args['user']) && 'root' === $assoc_args['user']) ? 'root' : 'php';
                $format = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';
                $info   = ServerInspector::inspect($mode);

                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($info));
                    break;
                }

                $os      = (array) ($info['os'] ?? []);
                $runtime = (array) ($info['runtime'] ?? []);
                $summary = (array) ($info['summary'] ?? []);
                $procs   = (array) ($info['processes'] ?? []);

                \WP_CLI::log('=== Gratis Security: Server Diagnostic Wizard ===');
                \WP_CLI::log("OS:           {$os['pretty_name']} ({$os['machine']} / {$os['audit_arch']}, init: {$os['init_system']})");
                \WP_CLI::log("PHP Runtime:  {$runtime['user']}:{$runtime['group']} (SELinux: {$runtime['selinux']})");
                \WP_CLI::log("Summary:      {$summary['overall']} ({$summary['passed']}/{$summary['total']} checks passed)");
                \WP_CLI::log('Processes:    ' . (empty($procs) ? 'none' : count($procs) . ' inotifywait process(es) running'));

                if (!empty($procs)) {
                    $proc_rows = array_map(static fn(array $p): array => [
                        'PID'     => (string) ($p['pid'] ?? ''),
                        'User'    => (string) ($p['user'] ?? ''),
                        'Matches' => !empty($p['matches_web_dir']) ? 'yes' : 'no',
                        'Command' => (string) ($p['cmd'] ?? ''),
                    ], $procs);
                    \WP_CLI\Utils\format_items('table', $proc_rows, ['PID', 'User', 'Matches', 'Command']);
                }

                $check_rows = array_map(static fn(array $c): array => [
                    'ID'     => (string) ($c['id'] ?? ''),
                    'Check'  => (string) ($c['label'] ?? ''),
                    'Status' => strtoupper((string) ($c['status'] ?? '')),
                    'Detail' => (string) ($c['detail'] ?? ''),
                ], (array) ($info['checks'] ?? []));
                \WP_CLI\Utils\format_items('table', $check_rows, ['ID', 'Check', 'Status', 'Detail']);

                \WP_CLI::log("\n--- Wizard Steps (mode: {$mode}) ---");
                foreach ((array) ($info['recommendations']['steps'] ?? []) as $idx => $step) {
                    $st = strtoupper((string) ($step['status'] ?? ''));
                    \WP_CLI::log(($idx + 1) . ". [{$st}] {$step['title']} — {$step['reason']}");
                    if (!empty($step['command']) && 'done' !== ($step['status'] ?? '')) {
                        \WP_CLI::log($step['command'] . "\n");
                    }
                }
                break;

            case 'trail':
                $format = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';
                $res    = EventMonitor::trail();

                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    break;
                }

                \WP_CLI::log(sprintf(
                    'Trailed %d sources, %d lines, %d new detections',
                    (int) ($res['sources_checked'] ?? 0),
                    (int) ($res['lines_read'] ?? 0),
                    (int) ($res['new_detections'] ?? 0)
                ));

                if (!empty($res['detections'])) {
                    $rows = array_map(static fn(array $d): array => [
                        'ID'        => (string) ($d['id'] ?? ''),
                        'Time'      => (string) ($d['event_time'] ?? ''),
                        'Severity'  => strtoupper((string) ($d['severity'] ?? '')),
                        'Rule'      => (string) ($d['rule'] ?? ''),
                        'Path'      => (string) ($d['path'] ?? ''),
                        'Component' => (string) ($d['component'] ?? ''),
                    ], (array) $res['detections']);
                    \WP_CLI\Utils\format_items('table', $rows, ['ID', 'Time', 'Severity', 'Rule', 'Path', 'Component']);
                }
                break;

            case 'detections':
                $format  = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';
                $filters = [
                    'severity'  => (string) ($assoc_args['severity'] ?? ''),
                    'status'    => (string) ($assoc_args['status'] ?? ''),
                    'component' => (string) ($assoc_args['component'] ?? ''),
                    'search'    => (string) ($assoc_args['search'] ?? ''),
                    'limit'     => isset($assoc_args['limit']) ? (int) $assoc_args['limit'] : 100,
                ];
                $res = EventMonitor::query_detections($filters);

                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    break;
                }

                if (empty($res['detections'])) {
                    \WP_CLI::log('No detections found.');
                    break;
                }

                $rows = array_map(static fn(array $d): array => [
                    'ID'        => (string) ($d['id'] ?? ''),
                    'Time'      => (string) ($d['event_time'] ?? ''),
                    'Severity'  => strtoupper((string) ($d['severity'] ?? '')),
                    'Status'    => (string) ($d['status'] ?? ''),
                    'Rule'      => (string) ($d['rule'] ?? ''),
                    'Path'      => (string) ($d['path'] ?? ''),
                    'Component' => (string) ($d['component'] ?? ''),
                ], (array) $res['detections']);
                \WP_CLI\Utils\format_items('table', $rows, ['ID', 'Time', 'Severity', 'Status', 'Rule', 'Path', 'Component']);
                break;

            case 'logs':
                $format  = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';
                $filters = [
                    'search'          => (string) ($assoc_args['search'] ?? ''),
                    'event'           => (string) ($assoc_args['event'] ?? ''),
                    'component'       => (string) ($assoc_args['component'] ?? ''),
                    'source'          => (string) ($assoc_args['source'] ?? ''),
                    'since'           => (string) ($assoc_args['since'] ?? 'all'),
                    'only_suspicious' => isset($assoc_args['suspicious']),
                    'limit'           => isset($assoc_args['limit']) ? (int) $assoc_args['limit'] : 100,
                ];
                $res = EventMonitor::query_events($filters);

                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    break;
                }

                if (empty($res['events'])) {
                    \WP_CLI::log('No matching log events found.');
                    break;
                }

                $rows = array_map(static fn(array $e): array => [
                    'Time'      => (string) ($e['time'] ?? ''),
                    'Source'    => (string) ($e['source'] ?? ''),
                    'Event'     => (string) ($e['event'] ?? ''),
                    'Component' => (string) ($e['component'] ?? ''),
                    'Path'      => (string) ($e['path'] ?? ''),
                ], (array) $res['events']);
                \WP_CLI\Utils\format_items('table', $rows, ['Time', 'Source', 'Event', 'Component', 'Path']);
                break;

            case 'purge-verified':
                $format = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';
                $res    = EventMonitor::purge_verified_detections();

                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    break;
                }

                \WP_CLI::success("Purged {$res['removed']} verified false-positive detection(s); {$res['remaining']} remaining.");
                break;

            default:
                \WP_CLI::error("Unknown fim action '{$action}'. Use: status, scan, diff, baseline, instructions, wizard, trail, detections, logs, purge-verified.");
        }
    }

    /**
     * Set, reset, or disable a user's two-factor authentication secret.
     *
     * ## OPTIONS
     *
     * <action>
     * : What to do. One of: set, reset, disable.
     *   - set/reset generate a brand-new secret and store it (overwriting any existing one).
     *   - disable removes the user's 2FA secret entirely.
     *
     * <user>
     * : User ID or login name.
     *
     * ## EXAMPLES
     *
     *     wp gratis-security 2fa set admin
     *     wp gratis-security 2fa reset 1
     *     wp gratis-security 2fa disable editor
     *
     * @subcommand 2fa
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args: action, user.
     * @param array<string,string> $assoc_args Associative args (unused).
     */
    // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP-CLI command signature.
    public function manage_2fa($args, $assoc_args): void {
        $action     = isset($args[0]) ? strtolower((string) $args[0]) : '';
        $identifier = isset($args[1]) ? (string) $args[1] : '';

        $user = is_numeric($identifier)
            ? get_user_by('id', (int) $identifier)
            : get_user_by('login', $identifier);

        if (!$user instanceof \WP_User) {
            \WP_CLI::error("User not found: {$identifier}");
            return;
        }

        switch ($action) {
            case 'set':
            case 'reset':
                $secret = TwoFactor::generateSecret();
                TwoFactor::setSecret($user->ID, $secret);
                \WP_CLI::log("Manual key: {$secret}");
                \WP_CLI::log('otpauth:    ' . TwoFactor::provisioningUri($user, $secret));
                \WP_CLI::log('Add it to an authenticator app (Google Authenticator, Aegis, 1Password, etc.).');
                \WP_CLI::success("2FA secret stored for {$user->user_login} (#{$user->ID}).");
                break;

            case 'disable':
                TwoFactor::clearForUser($user->ID);
                \WP_CLI::success("2FA disabled for {$user->user_login} (#{$user->ID}).");
                break;

            default:
                \WP_CLI::error("Unknown action '{$action}'. Use one of: set, reset, disable.");
        }
    }

    /**
     * Generate a 2FA secret for a user (alias of `2fa set`).
     * <user> : User ID or login.
     *
     * @subcommand 2fa-setup
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args.
     * @param array<string,string> $assoc_args Associative args (unused).
     */
    public function twofa_setup($args, $assoc_args): void {
        $this->manage_2fa(['set', isset($args[0]) ? (string) $args[0] : ''], $assoc_args);
    }

    /**
     * Diagnose security posture or run 1-click PHP auto-configuration.
     *
     * ## OPTIONS
     *
     * [--auto]
     * : Run PHP-first auto-configuration (hardens storage, sets safe defaults, syncs signatures, schedules cron, purges verified FIM false positives, runs initial scans).
     *
     * [--waf-mode=<mode>]
     * : WAF mode for --auto (monitor or block). Default: monitor.
     *
     * [--no-scans]
     * : Skip initial FIM and malware scans when running --auto.
     *
     * [--user=<mode>]
     * : Service user mode for server diagnostics (php or root). Default: php.
     *
     * [--format=<format>]
     * : Output format (table or json). Default: table.
     *
     * @subcommand wizard
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args (unused).
     * @param array<string,string> $assoc_args Associative args.
     */
    // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP-CLI command signature.
    public function wizard($args, $assoc_args): void {
        $format    = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';
        $user_mode = (isset($assoc_args['user']) && 'root' === strtolower((string) $assoc_args['user'])) ? 'root' : 'php';

        if (isset($assoc_args['auto'])) {
            $waf_mode  = isset($assoc_args['waf-mode']) ? strtolower((string) $assoc_args['waf-mode']) : 'monitor';
            $run_scans = !isset($assoc_args['no-scans']);
            $res       = SetupWizard::run_auto_configure([
                'waf_mode'  => $waf_mode,
                'run_scans' => $run_scans,
            ]);

            if ('json' === $format) {
                \WP_CLI::line(self::encode_json($res));
                return;
            }

            $rows = [];
            foreach ((array) ($res['steps'] ?? []) as $step_name => $step_data) {
                $step_arr = (array) $step_data;
                $status   = !empty($step_arr['skipped']) ? 'SKIPPED' : (!empty($step_arr['ok']) ? 'OK' : 'FAIL');
                $rows[]   = [
                    'Step'   => (string) $step_name,
                    'Status' => $status,
                    'Detail' => self::format_step_detail($step_arr),
                ];
            }
            if (!empty($rows)) {
                \WP_CLI\Utils\format_items('table', $rows, ['Step', 'Status', 'Detail']);
            }

            $audit = (array) ($res['audit'] ?? []);
            \WP_CLI::log('Score: ' . (int) ($audit['score'] ?? 0) . '/100 (Grade ' . (string) ($audit['grade'] ?? 'F') . ')');
            \WP_CLI::success('Security auto-configuration complete.');
            return;
        }

        $diag = SetupWizard::diagnose($user_mode);
        if ('json' === $format) {
            \WP_CLI::line(self::encode_json($diag));
            return;
        }

        $audit = (array) ($diag['audit'] ?? []);
        $php   = (array) ($diag['php_capabilities'] ?? []);
        $srv   = (array) ($diag['server'] ?? []);
        $exts  = [];
        foreach ((array) ($php['extensions'] ?? []) as $ext => $loaded) {
            $exts[] = $ext . ':' . ($loaded ? 'on' : 'off');
        }

        \WP_CLI::log('=== Gratis Security: Setup Wizard Diagnostics ===');
        \WP_CLI::log('Score:             ' . (int) ($audit['score'] ?? 0) . '/100 (Grade ' . (string) ($audit['grade'] ?? 'F') . ')');
        \WP_CLI::log('Wizard Completed:  ' . ('' !== (string) ($diag['wizard_completed_at'] ?? '') ? (string) $diag['wizard_completed_at'] : 'Not yet'));
        \WP_CLI::log('Storage Writable:  ' . (!empty($php['storage_writable']) ? 'Yes' : 'No') . ' (' . (string) ($php['storage_dir'] ?? '') . ')');
        \WP_CLI::log('WP-Cron:           ' . (string) ($php['wp_cron_note'] ?? ''));
        \WP_CLI::log('PHP Extensions:    ' . implode(', ', $exts));
        $clam = (array) ($php['clamav'] ?? []);
        \WP_CLI::log('ClamAV:            ' . (!empty($clam['available']) ? ((string) ($clam['type'] ?? 'available') . ' (' . (string) ($clam['binary'] ?? '') . ')') : 'Not installed'));

        $srv_checks = (array) ($srv['checks'] ?? []);
        if (!empty($srv_checks)) {
            \WP_CLI::log("\n--- Server Checks (mode: {$user_mode}) ---");
            $check_rows = array_map(static fn(array $c): array => [
                'ID'     => (string) ($c['id'] ?? ''),
                'Check'  => (string) ($c['label'] ?? ''),
                'Status' => strtoupper((string) ($c['status'] ?? '')),
                'Detail' => (string) ($c['detail'] ?? ''),
            ], $srv_checks);
            \WP_CLI\Utils\format_items('table', $check_rows, ['ID', 'Check', 'Status', 'Detail']);
        }

        $upgrades = (array) ($diag['optional_os_upgrades'] ?? []);
        if (!empty($upgrades)) {
            \WP_CLI::log("\n--- Optional OS-Level Commands ---");
            foreach ($upgrades as $idx => $up) {
                \WP_CLI::log(($idx + 1) . '. ' . (string) ($up['title'] ?? '') . ' — ' . (string) ($up['why_manual'] ?? ''));
                if (!empty($up['command'])) {
                    \WP_CLI::log((string) $up['command'] . "\n");
                }
            }
        }
    }

    /**
     * Run the pure-PHP WordPress and plugin security posture audit.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : Output format (table or json). Default: table.
     *
     * @subcommand audit
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args (unused).
     * @param array<string,string> $assoc_args Associative args.
     */
    // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP-CLI command signature.
    public function audit($args, $assoc_args): void {
        $format = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';
        $res    = SecurityAudit::run();

        if ('json' === $format) {
            \WP_CLI::line(self::encode_json($res));
            return;
        }

        $rows = array_map(static fn(array $c): array => [
            'ID'     => (string) ($c['id'] ?? ''),
            'Check'  => (string) ($c['label'] ?? ''),
            'Status' => strtoupper((string) ($c['status'] ?? '')),
            'Weight' => (string) (int) ($c['weight'] ?? 0),
            'Detail' => (string) ($c['detail'] ?? ''),
        ], (array) ($res['checks'] ?? []));

        if (!empty($rows)) {
            \WP_CLI\Utils\format_items('table', $rows, ['ID', 'Check', 'Status', 'Weight', 'Detail']);
        }

        \WP_CLI::log('Score: ' . (int) ($res['score'] ?? 0) . '/100 (Grade ' . (string) ($res['grade'] ?? 'F') . ')');
    }

    /**
     * View status or update malware/WAF/checksum signature feeds.
     *
     * ## OPTIONS
     *
     * [<action>]
     * : Action: status (default) or update.
     *
     * [--format=<format>]
     * : Output format (table or json). Default: table.
     *
     * @subcommand signatures
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args: [action].
     * @param array<string,string> $assoc_args Associative args.
     */
    public function signatures($args, $assoc_args): void {
        $action = isset($args[0]) ? strtolower((string) $args[0]) : 'status';
        $format = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';

        switch ($action) {
            case 'status':
                $res = SignatureFeed::get_status();
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    return;
                }
                \WP_CLI::log('Signature Feed Version: ' . (string) ($res['version'] ?? ''));
                \WP_CLI::log('Last Updated:           ' . ('' !== (string) ($res['last_updated'] ?? '') ? (string) $res['last_updated'] : 'Built-in only'));
                $counts = (array) ($res['counts'] ?? []);
                $rows   = [
                    ['Metric' => 'Malware Rules', 'Count' => (string) (int) ($counts['malware_rules'] ?? 0)],
                    ['Metric' => 'Request Rules', 'Count' => (string) (int) ($counts['request_rules'] ?? 0)],
                    ['Metric' => 'Bad Hashes', 'Count' => (string) (int) ($counts['bad_hashes'] ?? 0)],
                    ['Metric' => 'Feed IPs', 'Count' => (string) (int) ($counts['feed_ips'] ?? 0)],
                    ['Metric' => 'WP Checksums', 'Count' => (string) (int) ($counts['wp_checksums'] ?? 0)],
                ];
                \WP_CLI\Utils\format_items('table', $rows, ['Metric', 'Count']);
                break;

            case 'update':
                $res = SignatureFeed::update();
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    return;
                }
                $counts = (array) ($res['counts'] ?? []);
                $errors = (array) ($res['errors'] ?? []);
                \WP_CLI::log('Signature Feed Version: ' . (string) ($res['version'] ?? ''));
                \WP_CLI::log('Last Updated:           ' . (string) ($res['last_updated'] ?? ''));
                \WP_CLI::log(sprintf(
                    'Counts — Malware: %d, Request: %d, Bad Hashes: %d, Feed IPs: %d, WP Checksums: %d',
                    (int) ($counts['malware_rules'] ?? 0),
                    (int) ($counts['request_rules'] ?? 0),
                    (int) ($counts['bad_hashes'] ?? 0),
                    (int) ($counts['feed_ips'] ?? 0),
                    (int) ($counts['wp_checksums'] ?? 0)
                ));
                if (!empty($errors)) {
                    foreach ($errors as $err) {
                        \WP_CLI::warning((string) $err);
                    }
                }
                \WP_CLI::success('Signature feeds updated.');
                break;

            default:
                \WP_CLI::error("Unknown signatures action '{$action}'. Use: status, update.");
        }
    }

    /**
     * Manage quarantined malware files.
     *
     * ## OPTIONS
     *
     * [<action>]
     * : Action: list (default), restore, delete, add.
     *
     * [<file_or_id>]
     * : Quarantine ID (for restore/delete) or relative project file path (for add).
     *
     * [--format=<format>]
     * : Output format (table or json). Default: table.
     *
     * @subcommand quarantine
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args: [action], [file_or_id].
     * @param array<string,string> $assoc_args Associative args.
     */
    public function quarantine($args, $assoc_args): void {
        $action = isset($args[0]) ? strtolower((string) $args[0]) : 'list';
        $target = isset($args[1]) ? (string) $args[1] : '';
        $format = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';

        switch ($action) {
            case 'list':
                $items = MalwareScanner::list_quarantine();
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($items));
                    return;
                }
                if (empty($items)) {
                    \WP_CLI::log('Quarantine is empty.');
                    return;
                }
                $rows = array_map(static fn(array $item): array => [
                    'ID'             => (string) ($item['id'] ?? ''),
                    'Path'           => (string) ($item['original_rel_path'] ?? ''),
                    'Size'           => isset($item['size']) ? (string) (int) $item['size'] : '0',
                    'Quarantined At' => (string) ($item['quarantined_at'] ?? ''),
                    'Reason'         => (string) ($item['reason'] ?? ''),
                ], $items);
                \WP_CLI\Utils\format_items('table', $rows, ['ID', 'Path', 'Size', 'Quarantined At', 'Reason']);
                break;

            case 'restore':
                if ('' === $target) {
                    \WP_CLI::error('Provide a quarantine ID: wp gratis-security quarantine restore <id>');
                    return;
                }
                $res = MalwareScanner::restore_quarantine($target);
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    return;
                }
                if (empty($res['success'])) {
                    \WP_CLI::error((string) ($res['error'] ?? 'Failed to restore quarantined file.'));
                    return;
                }
                \WP_CLI::success('Restored file to ' . (string) ($res['restored_path'] ?? $target));
                break;

            case 'delete':
                if ('' === $target) {
                    \WP_CLI::error('Provide a quarantine ID: wp gratis-security quarantine delete <id>');
                    return;
                }
                $res = MalwareScanner::delete_quarantine($target);
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    return;
                }
                if (empty($res['success'])) {
                    \WP_CLI::error((string) ($res['error'] ?? 'Failed to delete quarantined file.'));
                    return;
                }
                \WP_CLI::success("Deleted quarantined item {$target}.");
                break;

            case 'add':
                if ('' === $target) {
                    \WP_CLI::error('Provide a relative file path: wp gratis-security quarantine add <path>');
                    return;
                }
                $res = MalwareScanner::quarantine_file($target);
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    return;
                }
                if (empty($res['success'])) {
                    \WP_CLI::error((string) ($res['error'] ?? 'Failed to quarantine file.'));
                    return;
                }
                $item = (array) ($res['item'] ?? []);
                \WP_CLI::success('Quarantined ' . (string) ($item['original_rel_path'] ?? $target) . ' (ID: ' . (string) ($item['id'] ?? '') . ').');
                break;

            default:
                \WP_CLI::error("Unknown quarantine action '{$action}'. Use: list, restore, delete, add.");
        }
    }

    /**
     * Inspect malicious requests, IP rules, and temporary auto-bans.
     *
     * ## OPTIONS
     *
     * [<action>]
     * : Action: list (default), clear, block-ip, unblock-ip, allow-ip, unban, bans.
     *
     * [<ip>]
     * : IP or CIDR for block-ip, unblock-ip, allow-ip, unban, or optional filter for list.
     *
     * [--note=<text>]
     * : Note when adding an IP rule.
     *
     * [--category=<cat>]
     * : Filter list by threat category.
     *
     * [--severity=<sev>]
     * : Filter list by severity (critical, high, medium, low).
     *
     * [--action=<action>]
     * : Filter list by action (blocked or logged).
     *
     * [--since=<window>]
     * : Filter list by time window (1h, 24h, 7d, all).
     *
     * [--limit=<n>]
     * : Maximum rows for list. Default: 50.
     *
     * [--format=<format>]
     * : Output format (table or json). Default: table.
     *
     * @subcommand requests
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args: [action], [ip].
     * @param array<string,string> $assoc_args Associative args.
     */
    public function requests($args, $assoc_args): void {
        $action = isset($args[0]) ? strtolower((string) $args[0]) : 'list';
        $ip     = isset($args[1]) ? trim((string) $args[1]) : '';
        $format = isset($assoc_args['format']) ? strtolower((string) $assoc_args['format']) : 'table';

        switch ($action) {
            case 'list':
                $filters = [
                    'ip'       => $ip,
                    'category' => (string) ($assoc_args['category'] ?? ''),
                    'severity' => (string) ($assoc_args['severity'] ?? ''),
                    'action'   => (string) ($assoc_args['action'] ?? ''),
                    'since'    => (string) ($assoc_args['since'] ?? 'all'),
                    'limit'    => isset($assoc_args['limit']) ? (int) $assoc_args['limit'] : 50,
                ];
                $res = RequestGuard::query_requests($filters);
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    return;
                }
                $entries = (array) ($res['requests'] ?? []);
                if (empty($entries)) {
                    \WP_CLI::log('No matching requests recorded.');
                    return;
                }
                $rows = array_map(static fn(array $e): array => [
                    'Time'     => (string) ($e['time'] ?? ''),
                    'IP'       => (string) ($e['ip'] ?? ''),
                    'Action'   => strtoupper((string) ($e['action'] ?? '')),
                    'Severity' => strtoupper((string) ($e['severity'] ?? '')),
                    'Category' => (string) ($e['category'] ?? ''),
                    'Rule'     => (string) ($e['rule'] ?? ''),
                    'URI'      => (string) ($e['uri'] ?? ''),
                ], $entries);
                \WP_CLI\Utils\format_items('table', $rows, ['Time', 'IP', 'Action', 'Severity', 'Category', 'Rule', 'URI']);
                break;

            case 'clear':
                RequestGuard::clear_requests();
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json(['success' => true]));
                    return;
                }
                \WP_CLI::success('Malicious request log cleared.');
                break;

            case 'block-ip':
            case 'allow-ip':
                if ('' === $ip) {
                    \WP_CLI::error("Provide an IP or CIDR: wp gratis-security requests {$action} <ip>");
                    return;
                }
                $list = ('allow-ip' === $action) ? 'allowlist' : 'blocklist';
                $note = (string) ($assoc_args['note'] ?? '');
                $res  = RequestGuard::add_ip_rule($ip, $list, $note);
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json($res));
                    return;
                }
                if (empty($res['success'])) {
                    \WP_CLI::error((string) ($res['error'] ?? 'Failed to add IP rule.'));
                    return;
                }
                \WP_CLI::success("Added {$ip} to {$list}.");
                break;

            case 'unblock-ip':
                if ('' === $ip) {
                    \WP_CLI::error('Provide an IP or CIDR: wp gratis-security requests unblock-ip <ip>');
                    return;
                }
                $ok = RequestGuard::remove_ip_rule($ip, 'blocklist');
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json(['success' => $ok, 'ip' => $ip, 'list' => 'blocklist']));
                    return;
                }
                if ($ok) {
                    \WP_CLI::success("Removed {$ip} from blocklist.");
                } else {
                    \WP_CLI::warning("{$ip} was not in blocklist.");
                }
                break;

            case 'unban':
                if ('' === $ip) {
                    \WP_CLI::error('Provide an IP: wp gratis-security requests unban <ip>');
                    return;
                }
                $ok = RequestGuard::unban_ip($ip);
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json(['success' => $ok, 'ip' => $ip]));
                    return;
                }
                if ($ok) {
                    \WP_CLI::success("Removed active auto-ban for {$ip}.");
                } else {
                    \WP_CLI::warning("No active auto-ban found for {$ip}.");
                }
                break;

            case 'bans':
                $bans = RequestGuard::get_active_bans();
                if ('json' === $format) {
                    \WP_CLI::line(self::encode_json(array_values($bans)));
                    return;
                }
                if (empty($bans)) {
                    \WP_CLI::log('No active IP bans.');
                    return;
                }
                $rows = array_map(static fn(array $b): array => [
                    'IP'      => (string) ($b['ip'] ?? ''),
                    'Expires' => (string) ($b['expires_at'] ?? ''),
                    'Minutes' => (string) (int) ($b['minutes'] ?? 0),
                    'Reason'  => (string) ($b['reason'] ?? ''),
                ], array_values($bans));
                \WP_CLI\Utils\format_items('table', $rows, ['IP', 'Expires', 'Minutes', 'Reason']);
                break;

            default:
                \WP_CLI::error("Unknown requests action '{$action}'. Use: list, clear, block-ip, unblock-ip, allow-ip, unban, bans.");
        }
    }

    private static function encode_json(mixed $data): string {
        $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        if (function_exists('wp_json_encode')) {
            $encoded = wp_json_encode($data, $flags);
            return is_string($encoded) ? $encoded : '{}';
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Fallback when executed outside WordPress runtime.
        $encoded = json_encode($data, $flags);
        return is_string($encoded) ? $encoded : '{}';
    }

    /**
     * @param array<string,mixed> $step
     */
    private static function format_step_detail(array $step): string {
        $parts = [];
        foreach ($step as $k => $v) {
            if ('ok' === $k || 'skipped' === $k) {
                continue;
            }
            if (is_array($v)) {
                $parts[] = $k . '=' . (string) wp_json_encode($v, JSON_UNESCAPED_SLASHES);
            } elseif (is_bool($v)) {
                $parts[] = $k . '=' . ($v ? 'true' : 'false');
            } else {
                $parts[] = $k . '=' . (string) $v;
            }
        }
        return implode(', ', $parts);
    }
}
