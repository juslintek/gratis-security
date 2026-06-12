<?php declare(strict_types=1);
namespace Gratis\Security\CLI;

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
        $log = get_option('gratis_security_blocks', []);
        if (empty($log)) {
            \WP_CLI::log('No blocks recorded.');
            return;
        }
        $recent = array_slice(array_reverse($log), 0, 20);
        $rows   = array_map(fn($e) => [
            'Time'   => $e['time'],
            'IP'     => $e['ip'],
            'Reason' => $e['reason'],
        ], $recent);
        \WP_CLI\Utils\format_items('table', $rows, ['Time', 'IP', 'Reason']);
    }

    /**
     * Generate 2FA secret for a user.
     * <user_id> : User ID.
     *
     * @subcommand 2fa-setup
     * @when after_wp_load
     *
     * @param array<int,string>    $args       Positional args.
     * @param array<string,string> $assoc_args Associative args (unused).
     */
    // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP-CLI command signature.
    public function twofa_setup($args, $assoc_args): void {
        $user_id = (int) $args[0];
        $secret = TwoFactor::generateSecret();
        update_user_meta($user_id, '_gratis_2fa_secret', $secret);
        \WP_CLI::log("2FA Secret: {$secret}");
        \WP_CLI::log('Add to authenticator app (Google Authenticator, Authy, etc.)');
        \WP_CLI::success("2FA enabled for user #{$user_id}");
    }
}
