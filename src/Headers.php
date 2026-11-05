<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Emits hardening response headers on the front end. Hooked late on `send_headers`
 * so it can override theme/plugin output but still be filtered by site owners.
 */
final class Headers {

    /**
     * Send the configured security headers.
     */
    public static function send(): void {
        if (headers_sent()) {
            return;
        }

        // Strip the PHP version banner (F-03). The expose_php ini directive cannot
        // be changed at runtime, so the X-Powered-By header is removed here. This
        // runs regardless of the headers toggle or context — hiding the version
        // never breaks output, and the banner leaks on admin requests too.
        header_remove('X-Powered-By');

        if (!Settings::get_bool('headers_enabled', true)) {
            return;
        }
        if (is_admin()) {
            return;
        }

        foreach (self::headers() as $name => $value) {
            if ('' !== $value) {
                header($name . ': ' . $value);
            }
        }
    }

    /**
     * Build the header map, filterable for site-specific policies.
     *
     * @return array<string,string>
     */
    public static function headers(): array {
        $headers = [
            'X-Frame-Options'        => 'SAMEORIGIN',
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy'        => 'strict-origin-when-cross-origin',
            'X-XSS-Protection'       => '1; mode=block',
            'Permissions-Policy'     => 'geolocation=(), microphone=(), camera=()',
        ];

        $csp = Settings::get_string('csp', '');
        $csp = $csp ?: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:";
        $headers['Content-Security-Policy'] = $csp;

        if (is_ssl()) {
            $headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
        }

        /**
         * Filter the security headers sent on the front end.
         *
         * @param array<string,string> $headers Map of header name => value.
         */
        $headers = apply_filters('gratis_security_headers', $headers);

        return is_array($headers) ? $headers : [];
    }
}
