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
