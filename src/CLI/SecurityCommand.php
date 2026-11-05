<?php declare(strict_types=1);
namespace Gratis\Security\CLI;

use Gratis\Security\FileIntegrity;
use Gratis\Security\MalwareScanner;
use Gratis\Security\TwoFactor;

final class SecurityCommand {

    /**
     * Scan for malware.
     * [--dir=<path>] : Directory to scan.
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args (unused).
     * @param array<string,string> $assoc_args Associative args.
     */
    // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP-CLI command signature.
    public function scan($args, $assoc_args): void {
        $dir = $assoc_args['dir'] ?? WP_CONTENT_DIR;
        \WP_CLI::log("Scanning {$dir} for malware...");
        $result = MalwareScanner::scan($dir);
        \WP_CLI::log("Files scanned: {$result['scanned']}");
        if (empty($result['suspicious'])) {
            \WP_CLI::success('No suspicious files found.');
            return;
        }
        \WP_CLI::warning(count($result['suspicious']) . ' suspicious file(s):');
        foreach ($result['suspicious'] as $s) {
            \WP_CLI::log("  ✗ {$s['file']} — {$s['reason']}");
        }
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
     * : One of: status, scan, diff, baseline, instructions.
     *
     * [<file>]
     * : Relative file path for `diff`.
     *
     * [--check-vendor]
     * : Also verify COMPOSER-MANIFEST.sha256 during scan.
     *
     * ## EXAMPLES
     *
     *     wp gratis-security fim status
     *     wp gratis-security fim scan
     *     wp gratis-security fim scan --check-vendor
     *     wp gratis-security fim diff web/app/mu-plugins/vlt-admin-menu.php
     *     wp gratis-security fim baseline
     *     wp gratis-security fim instructions
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

            default:
                \WP_CLI::error("Unknown fim action '{$action}'. Use: status, scan, diff, baseline, instructions.");
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
}
