<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Global security settings, stored as a single option array and exposed via the
 * WordPress Settings API on a page under the Settings menu. Also renders the WAF
 * block log and the file-integrity report.
 */
final class Settings {

    /** Option name holding all settings. */
    public const OPTION = 'gratis_security_settings';

    /** Settings group / page slug. */
    private const GROUP = 'gratis_security_settings_group';
    private const PAGE  = 'gratis-security';

    /**
     * Default values for every setting.
     *
     * @return array<string,mixed>
     */
    public static function defaults(): array {
        return [
            'waf_enabled'      => 1,
            'block_xmlrpc'     => 1,
            'headers_enabled'  => 1,
            'csp'              => '',
            'login_protection' => 1,
            'login_max_tries'  => 5,
            'login_lockout'    => 15,
            'integrity_enabled' => 1,
            'twofa_enabled'    => 0,
        ];
    }

    /**
     * Fetch the merged settings array (stored values over defaults).
     *
     * @return array<string,mixed>
     */
    public static function all(): array {
        $stored = get_option(self::OPTION, []);
        if (!is_array($stored)) {
            $stored = [];
        }
        return array_merge(self::defaults(), $stored);
    }

    /**
     * Boolean accessor for a single setting.
     */
    public static function get_bool(string $key, bool $fallback = false): bool {
        $all = self::all();
        return isset($all[$key]) ? (bool) $all[$key] : $fallback;
    }

    /**
     * Integer accessor for a single setting.
     */
    public static function get_int(string $key, int $fallback = 0): int {
        $all = self::all();
        return isset($all[$key]) ? (int) $all[$key] : $fallback;
    }

    /**
     * String accessor for a single setting.
     */
    public static function get_string(string $key, string $fallback = ''): string {
        $all = self::all();
        return isset($all[$key]) ? (string) $all[$key] : $fallback;
    }

    /**
     * Register the settings page under the Settings menu.
     */
    public static function register_menu(): void {
        add_options_page(
            __('Gratis Security', 'gratis-security'),
            __('Gratis Security', 'gratis-security'),
            'manage_options',
            self::PAGE,
            [__CLASS__, 'render_page']
        );
    }

    /**
     * Register the option and its sanitisation callback.
     */
    public static function register_settings(): void {
        register_setting(
            self::GROUP,
            self::OPTION,
            [
                'type'              => 'array',
                'sanitize_callback' => [__CLASS__, 'sanitize'],
                'default'           => self::defaults(),
            ]
        );
    }

    /**
     * Sanitise the incoming settings array.
     *
     * @param mixed $input Raw option input.
     * @return array<string,mixed>
     */
    public static function sanitize($input): array {
        $input = is_array($input) ? $input : [];
        return [
            'waf_enabled'       => empty($input['waf_enabled']) ? 0 : 1,
            'block_xmlrpc'      => empty($input['block_xmlrpc']) ? 0 : 1,
            'headers_enabled'   => empty($input['headers_enabled']) ? 0 : 1,
            'csp'               => isset($input['csp']) ? sanitize_text_field((string) $input['csp']) : '',
            'login_protection'  => empty($input['login_protection']) ? 0 : 1,
            'login_max_tries'   => isset($input['login_max_tries']) ? max(1, absint($input['login_max_tries'])) : 5,
            'login_lockout'     => isset($input['login_lockout']) ? max(1, absint($input['login_lockout'])) : 15,
            'integrity_enabled' => empty($input['integrity_enabled']) ? 0 : 1,
            'twofa_enabled'     => empty($input['twofa_enabled']) ? 0 : 1,
        ];
    }

    /**
     * Render the settings screen plus block log and integrity report.
     */
    public static function render_page(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'gratis-security'));
        }

        self::maybe_handle_actions();

        $settings = self::all();

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('Gratis Security', 'gratis-security') . '</h1>';
        echo '<p>' . esc_html__('Web application firewall, login protection, security headers, and file-integrity monitoring.', 'gratis-security') . '</p>';

        echo '<form method="post" action="options.php">';
        settings_fields(self::GROUP);
        echo '<table class="form-table" role="presentation"><tbody>';

        self::checkbox_row($settings, 'waf_enabled', __('Web Application Firewall', 'gratis-security'), __('Block SQL injection, XSS, and path-traversal request patterns.', 'gratis-security'));
        self::checkbox_row($settings, 'block_xmlrpc', __('Block XML-RPC', 'gratis-security'), __('Reject requests to xmlrpc.php (common brute-force vector).', 'gratis-security'));
        self::checkbox_row($settings, 'headers_enabled', __('Security headers', 'gratis-security'), __('Send X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and CSP on the front end.', 'gratis-security'));

        echo '<tr><th scope="row"><label for="gs_csp">' . esc_html__('Content-Security-Policy', 'gratis-security') . '</label></th><td>';
        echo '<input type="text" id="gs_csp" class="large-text" name="' . esc_attr(self::OPTION) . '[csp]" value="' . esc_attr((string) $settings['csp']) . '"> ';
        echo '<p class="description">' . esc_html__('Optional. Leave blank to omit the CSP header. Example: default-src \'self\'', 'gratis-security') . '</p>';
        echo '</td></tr>';

        self::checkbox_row($settings, 'login_protection', __('Login rate limiting', 'gratis-security'), __('Lock out an IP after too many failed login attempts.', 'gratis-security'));

        echo '<tr><th scope="row"><label for="gs_max_tries">' . esc_html__('Max failed attempts', 'gratis-security') . '</label></th><td>';
        echo '<input type="number" min="1" id="gs_max_tries" class="small-text" name="' . esc_attr(self::OPTION) . '[login_max_tries]" value="' . esc_attr((string) (int) $settings['login_max_tries']) . '">';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="gs_lockout">' . esc_html__('Lockout window (minutes)', 'gratis-security') . '</label></th><td>';
        echo '<input type="number" min="1" id="gs_lockout" class="small-text" name="' . esc_attr(self::OPTION) . '[login_lockout]" value="' . esc_attr((string) (int) $settings['login_lockout']) . '">';
        echo '</td></tr>';

        self::checkbox_row($settings, 'integrity_enabled', __('File integrity monitoring', 'gratis-security'), __('Detect changes to WordPress core files against a saved baseline.', 'gratis-security'));
        self::checkbox_row($settings, 'twofa_enabled', __('Two-factor authentication', 'gratis-security'), __('Require a TOTP code for administrator logins. Each administrator enables it on their own profile page (or via WP-CLI).', 'gratis-security'));

        echo '</tbody></table>';
        submit_button();
        echo '</form>';

        self::render_integrity_panel();
        self::render_block_log();

        echo '</div>';
    }

    /**
     * Output a single checkbox settings row.
     *
     * @param array<string,mixed> $settings Current settings.
     */
    private static function checkbox_row(array $settings, string $key, string $label, string $description): void {
        echo '<tr><th scope="row">' . esc_html($label) . '</th><td>';
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION) . '[' . esc_attr($key) . ']" value="1"' . checked((int) ($settings[$key] ?? 0), 1, false) . '> ';
        echo esc_html($description) . '</label>';
        echo '</td></tr>';
    }

    /**
     * Handle baseline build / log clear actions (nonce + capability gated).
     */
    private static function maybe_handle_actions(): void {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce verified per-action below.
        $action = isset($_POST['gratis_security_action']) ? sanitize_key(wp_unslash($_POST['gratis_security_action'])) : '';
        if ('' === $action) {
            return;
        }
        if (!current_user_can('manage_options')) {
            return;
        }
        check_admin_referer('gratis_security_action');

        if ('build_baseline' === $action) {
            $count = FileIntegrity::build_baseline();
            add_settings_error('gratis_security', 'baseline', sprintf(/* translators: %d: number of files. */ __('Integrity baseline saved (%d files).', 'gratis-security'), absint($count)), 'success');
        } elseif ('clear_blocks' === $action) {
            delete_option('gratis_security_blocks');
            add_settings_error('gratis_security', 'blocks', __('Block log cleared.', 'gratis-security'), 'success');
        }

        settings_errors('gratis_security');
    }

    /**
     * Render the file-integrity report panel.
     */
    private static function render_integrity_panel(): void {
        echo '<h2>' . esc_html__('File Integrity', 'gratis-security') . '</h2>';

        $baseline = get_option(FileIntegrity::OPTION, []);
        $built_at = is_array($baseline) && isset($baseline['built_at']) ? (string) $baseline['built_at'] : '';

        echo '<form method="post">';
        wp_nonce_field('gratis_security_action');
        echo '<input type="hidden" name="gratis_security_action" value="build_baseline">';
        if ('' !== $built_at) {
            echo '<p>' . esc_html(sprintf(/* translators: %s: datetime. */ __('Baseline captured: %s', 'gratis-security'), $built_at)) . '</p>';
        } else {
            echo '<p>' . esc_html__('No baseline captured yet. Build one to enable change detection.', 'gratis-security') . '</p>';
        }
        submit_button(__('Rebuild baseline', 'gratis-security'), 'secondary', 'submit', false);
        echo '</form>';

        if ('' === $built_at) {
            return;
        }

        $report = FileIntegrity::scan();
        if (empty($report['changed']) && empty($report['missing'])) {
            echo '<p>' . esc_html__('No core file changes detected.', 'gratis-security') . '</p>';
            return;
        }

        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('File', 'gratis-security') . '</th><th>' . esc_html__('Status', 'gratis-security') . '</th></tr></thead><tbody>';
        foreach ($report['changed'] as $file) {
            echo '<tr><td><code>' . esc_html((string) $file) . '</code></td><td>' . esc_html__('Modified', 'gratis-security') . '</td></tr>';
        }
        foreach ($report['missing'] as $file) {
            echo '<tr><td><code>' . esc_html((string) $file) . '</code></td><td>' . esc_html__('Missing', 'gratis-security') . '</td></tr>';
        }
        echo '</tbody></table>';
    }

    /**
     * Render the recent WAF block log.
     */
    private static function render_block_log(): void {
        echo '<h2>' . esc_html__('Recent Blocks', 'gratis-security') . '</h2>';

        $log = get_option('gratis_security_blocks', []);
        if (!is_array($log) || empty($log)) {
            echo '<p>' . esc_html__('No requests have been blocked.', 'gratis-security') . '</p>';
            return;
        }

        echo '<form method="post" style="margin-bottom:1em;">';
        wp_nonce_field('gratis_security_action');
        echo '<input type="hidden" name="gratis_security_action" value="clear_blocks">';
        submit_button(__('Clear log', 'gratis-security'), 'secondary', 'submit', false);
        echo '</form>';

        $recent = array_slice(array_reverse($log), 0, 50);
        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Time', 'gratis-security') . '</th><th>' . esc_html__('IP', 'gratis-security') . '</th><th>' . esc_html__('Reason', 'gratis-security') . '</th><th>' . esc_html__('URI', 'gratis-security') . '</th></tr></thead><tbody>';
        foreach ($recent as $entry) {
            echo '<tr>';
            echo '<td>' . esc_html((string) ($entry['time'] ?? '')) . '</td>';
            echo '<td>' . esc_html((string) ($entry['ip'] ?? '')) . '</td>';
            echo '<td>' . esc_html((string) ($entry['reason'] ?? '')) . '</td>';
            echo '<td><code>' . esc_html((string) ($entry['uri'] ?? '')) . '</code></td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }
}
