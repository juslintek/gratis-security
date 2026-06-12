<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Login brute-force protection. Tracks failed attempts per IP in a transient and
 * locks out the IP once the configured threshold is reached, for the configured
 * window. Successful logins reset the counter.
 */
final class LoginProtection {

    /** Transient key prefix for per-IP attempt counters. */
    private const PREFIX = 'gratis_sec_login_';

    /**
     * Register login hooks.
     */
    public static function init(): void {
        if (!Settings::get_bool('login_protection', true)) {
            return;
        }
        add_filter('authenticate', [__CLASS__, 'check_lockout'], 30, 1);
        add_action('wp_login_failed', [__CLASS__, 'record_failure']);
        add_action('wp_login', [__CLASS__, 'clear_on_success'], 10, 1);
    }

    /**
     * Block authentication while an IP is locked out.
     *
     * @param \WP_User|\WP_Error|null $user Current authentication result.
     * @return \WP_User|\WP_Error|null
     */
    public static function check_lockout($user) {
        $ip = self::client_ip();
        if ('' === $ip) {
            return $user;
        }

        $state = self::state($ip);
        $max   = Settings::get_int('login_max_tries', 5);

        if ($state['count'] >= $max && $state['until'] > time()) {
            $minutes = (int) ceil(($state['until'] - time()) / 60);
            return new \WP_Error(
                'gratis_security_locked',
                sprintf(
                    /* translators: %d: minutes remaining. */
                    esc_html__('Too many failed login attempts. Try again in %d minute(s).', 'gratis-security'),
                    absint(max(1, $minutes))
                )
            );
        }

        return $user;
    }

    /**
     * Increment the failure counter for the current IP.
     */
    public static function record_failure(): void {
        $ip = self::client_ip();
        if ('' === $ip) {
            return;
        }

        $window  = Settings::get_int('login_lockout', 15) * MINUTE_IN_SECONDS;
        $max     = Settings::get_int('login_max_tries', 5);
        $state   = self::state($ip);
        ++$state['count'];

        if ($state['count'] >= $max) {
            $state['until'] = time() + $window;
        }

        set_transient(self::PREFIX . md5($ip), $state, $window);
    }

    /**
     * Clear the counter after a successful login.
     */
    public static function clear_on_success(): void {
        $ip = self::client_ip();
        if ('' !== $ip) {
            delete_transient(self::PREFIX . md5($ip));
        }
    }

    /**
     * Fetch the stored attempt state for an IP.
     *
     * @return array{count:int,until:int}
     */
    private static function state(string $ip): array {
        $state = get_transient(self::PREFIX . md5($ip));
        if (!is_array($state)) {
            $state = [];
        }
        return [
            'count' => isset($state['count']) ? (int) $state['count'] : 0,
            'until' => isset($state['until']) ? (int) $state['until'] : 0,
        ];
    }

    /**
     * Resolve the client IP from the request.
     */
    private static function client_ip(): string {
        $raw = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        $ip  = filter_var($raw, FILTER_VALIDATE_IP);
        return false === $ip ? '' : (string) $ip;
    }
}
