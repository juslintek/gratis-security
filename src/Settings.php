<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Global security settings, stored as a single option array and exposed via the
 * WordPress Settings API. Features full File Integrity & Server Monitoring dashboard,
 * Red Hat server integration guides, and WAF block logs.
 */
final class Settings {

    /** Option name holding core plugin settings. */
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
            'waf_enabled'             => 0,
            'waf_mode'                => 'monitor',
            'block_xmlrpc'            => 1,
            'headers_enabled'         => 1,
            'csp'                     => '',
            'login_protection'        => 1,
            'login_max_tries'         => 5,
            'login_lockout'           => 15,
            'auto_ban_enabled'        => 1,
            'auto_ban_threshold'      => 5,
            'auto_ban_minutes'        => 60,
            'integrity_enabled'       => 1,
            'malware_auto_scan'       => 1,
            'use_clamav'              => 0,
            'signature_auto_update'   => 1,
            'sync_wp_checksums'       => 1,
            'signature_feed_url'      => '',
            'signature_feed_token'    => '',
            'ip_feed_url'             => '',
            'notify_email_on_fim'     => 1,
            'notify_email_on_malware' => 1,
            'twofa_enabled'           => 0,
            'wizard_completed_at'     => '',
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
        $merged = array_merge(self::defaults(), $stored);
        if (!array_key_exists('waf_mode', $stored) && !empty($stored['waf_enabled'])) {
            $merged['waf_mode'] = 'block';
        }
        return $merged;
    }

    public static function get_bool(string $key, bool $fallback = false): bool {
        $all = self::all();
        return isset($all[$key]) ? (bool) $all[$key] : $fallback;
    }

    public static function get_int(string $key, int $fallback = 0): int {
        $all = self::all();
        return isset($all[$key]) ? (int) $all[$key] : $fallback;
    }

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
     * Register settings and sanitisation.
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
     * Register AJAX hooks.
     */
    public static function register_ajax(): void {
        add_action('wp_ajax_gratis_fim_scan', [__CLASS__, 'ajax_scan']);
        add_action('wp_ajax_gratis_fim_diff', [__CLASS__, 'ajax_diff']);
        add_action('wp_ajax_gratis_fim_baseline', [__CLASS__, 'ajax_baseline']);
        add_action('wp_ajax_gratis_server_wizard', [__CLASS__, 'ajax_server_wizard']);
        add_action('wp_ajax_gratis_fim_trail', [__CLASS__, 'ajax_fim_trail']);
        add_action('wp_ajax_gratis_fim_logs', [__CLASS__, 'ajax_fim_logs']);
        add_action('wp_ajax_gratis_fim_detections', [__CLASS__, 'ajax_fim_detections']);

        add_action('wp_ajax_gratis_wizard_diagnose', [__CLASS__, 'ajax_wizard_diagnose']);
        add_action('wp_ajax_gratis_wizard_autoconfig', [__CLASS__, 'ajax_wizard_autoconfig']);
        add_action('wp_ajax_gratis_malware_scan', [__CLASS__, 'ajax_malware_scan']);
        add_action('wp_ajax_gratis_malware_action', [__CLASS__, 'ajax_malware_action']);
        add_action('wp_ajax_gratis_requests_query', [__CLASS__, 'ajax_requests_query']);
        add_action('wp_ajax_gratis_requests_ip', [__CLASS__, 'ajax_requests_ip']);
        add_action('wp_ajax_gratis_signatures_update', [__CLASS__, 'ajax_signatures_update']);
        add_action('wp_ajax_gratis_signatures_save_feeds', [__CLASS__, 'ajax_signatures_save_feeds']);
    }

    /**
     * Sanitise incoming settings while preserving keys owned by other tabs.
     *
     * @param mixed $input
     * @return array<string,mixed>
     */
    public static function sanitize($input): array {
        $input    = is_array($input) ? $input : [];
        $existing = function_exists('get_option') ? get_option(self::OPTION, []) : [];
        if (!is_array($existing)) {
            $existing = [];
        }
        $base = array_merge(self::defaults(), $existing);

        $is_general_form = !empty($input['_general_form']);
        $is_feeds_form   = !empty($input['_feeds_form']);

        $general_bool_keys = [
            'block_xmlrpc',
            'headers_enabled',
            'login_protection',
            'auto_ban_enabled',
            'integrity_enabled',
            'malware_auto_scan',
            'use_clamav',
            'notify_email_on_fim',
            'notify_email_on_malware',
            'twofa_enabled',
        ];
        foreach ($general_bool_keys as $key) {
            if ($is_general_form || array_key_exists($key, $input)) {
                $base[$key] = empty($input[$key]) ? 0 : 1;
            }
        }

        if (isset($input['waf_mode'])) {
            $mode = strtolower(trim((string) $input['waf_mode']));
            if (!in_array($mode, ['monitor', 'block', 'off'], true)) {
                $mode = 'monitor';
            }
            $base['waf_mode']    = $mode;
            $base['waf_enabled'] = ('block' === $mode) ? 1 : 0;
        } elseif ($is_general_form || array_key_exists('waf_enabled', $input)) {
            $waf_enabled         = empty($input['waf_enabled']) ? 0 : 1;
            $base['waf_enabled'] = $waf_enabled;
            $base['waf_mode']    = $waf_enabled ? 'block' : 'off';
        }

        if (array_key_exists('csp', $input)) {
            $base['csp'] = sanitize_text_field((string) $input['csp']);
        }
        if (array_key_exists('login_max_tries', $input)) {
            $base['login_max_tries'] = max(1, absint($input['login_max_tries']));
        }
        if (array_key_exists('login_lockout', $input)) {
            $base['login_lockout'] = max(1, absint($input['login_lockout']));
        }
        if (array_key_exists('auto_ban_threshold', $input)) {
            $base['auto_ban_threshold'] = max(1, absint($input['auto_ban_threshold']));
        }
        if (array_key_exists('auto_ban_minutes', $input)) {
            $base['auto_ban_minutes'] = max(1, absint($input['auto_ban_minutes']));
        }

        $feed_bool_keys = ['signature_auto_update', 'sync_wp_checksums'];
        foreach ($feed_bool_keys as $key) {
            if ($is_feeds_form || array_key_exists($key, $input)) {
                $base[$key] = empty($input[$key]) ? 0 : 1;
            }
        }

        foreach (['signature_feed_url', 'ip_feed_url'] as $url_key) {
            if (array_key_exists($url_key, $input)) {
                $raw_url = trim((string) $input[$url_key]);
                $base[$url_key] = '' !== $raw_url ? esc_url_raw($raw_url, ['https', 'http']) : '';
            }
        }
        if (array_key_exists('signature_feed_token', $input)) {
            $base['signature_feed_token'] = sanitize_text_field(trim((string) $input['signature_feed_token']));
        }
        if (array_key_exists('wizard_completed_at', $input)) {
            $base['wizard_completed_at'] = sanitize_text_field(trim((string) $input['wizard_completed_at']));
        }

        return $base;
    }

    /**
     * Render the admin page with navigation tabs.
     */
    public static function render_page(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'gratis-security'));
        }

        self::maybe_handle_actions();

        $default_tab = ('' === self::get_string('wizard_completed_at', '')) ? 'wizard' : 'fim';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $raw_tab = isset($_GET['tab']) ? sanitize_key((string) $_GET['tab']) : $default_tab;
        $tab     = ('blocks' === $raw_tab) ? 'requests' : $raw_tab;
        $allowed = ['wizard', 'fim', 'malware', 'requests', 'feeds', 'server', 'general'];
        if (!in_array($tab, $allowed, true)) {
            $tab = $default_tab;
        }

        $nonce = wp_create_nonce('gratis_fim_nonce');

        Admin\UiHelpers::render_styles();

        echo '<div class="wrap gratis-security-wrap">';
        echo '<h1>' . esc_html__('Gratis Security', 'gratis-security') . '</h1>';
        echo '<p class="description">' . esc_html__('Aukšto našumo serverio lygio failų stebėjimas, kenkėjiško kodo paieška, WAF apsauga ir parašų patikra be MySQL apkrovos.', 'gratis-security') . '</p>';

        self::render_tabs($tab);

        switch ($tab) {
            case 'wizard':
                Admin\WizardTab::render($nonce);
                break;
            case 'fim':
                self::render_fim_tab();
                break;
            case 'malware':
                Admin\MalwareTab::render($nonce);
                break;
            case 'requests':
                Admin\RequestsTab::render($nonce);
                break;
            case 'feeds':
                Admin\FeedsTab::render($nonce);
                break;
            case 'server':
                Admin\ServerTab::render($nonce);
                break;
            case 'general':
            default:
                self::render_general_tab();
                break;
        }

        echo '</div>';
    }

    /**
     * Render navigation tabs.
     */
    private static function render_tabs(string $active_tab): void {
        $tabs = [
            'wizard'   => __('Vedlys ir apžvalga', 'gratis-security'),
            'fim'      => __('Failų stebėjimas (FIM)', 'gratis-security'),
            'malware'  => __('Kenkėjiškas kodas', 'gratis-security'),
            'requests' => __('Užklausos ir WAF', 'gratis-security'),
            'feeds'    => __('Parašų atnaujinimai', 'gratis-security'),
            'server'   => __('Serveris ir žurnalai', 'gratis-security'),
            'general'  => __('Nustatymai', 'gratis-security'),
        ];

        echo '<nav class="nav-tab-wrapper" style="margin-bottom: 20px;">';
        foreach ($tabs as $key => $label) {
            $url   = admin_url('options-general.php?page=' . self::PAGE . '&tab=' . $key);
            $class = ($key === $active_tab) ? 'nav-tab nav-tab-active' : 'nav-tab';
            echo '<a href="' . esc_url($url) . '" class="' . esc_attr($class) . '">' . esc_html($label) . '</a>';
        }
        echo '</nav>';
    }

    /**
     * Render the File Integrity Monitoring dashboard tab.
     */
    private static function render_fim_tab(): void {
        $caps = FileIntegrity::detect_server_capabilities();
        $report = FileIntegrity::get_last_report();

        // Server capabilities status strip
        echo '<div class="gratis-card-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-bottom: 20px;">';

        // 1. Manifest / Revision Card
        echo '<div class="card" style="margin: 0; padding: 15px; border-left: 4px solid ' . ($caps['has_manifests'] ? '#46b450' : '#ffb900') . ';">';
        echo '<h3 style="margin: 0 0 5px 0;">' . esc_html__('Versijuoti parašai', 'gratis-security') . '</h3>';
        if ($caps['has_manifests']) {
            echo '<p style="margin: 0; font-size: 13px; color: #46b450; font-weight: 600;">✓ ' . esc_html__('Aktyvu (SOURCE-MANIFEST)', 'gratis-security') . '</p>';
            if (!empty($caps['revision'])) {
                echo '<p style="margin: 3px 0 0; font-size: 12px; color: #666;">Rev: <code>' . esc_html(substr((string) $caps['revision'], 0, 8)) . '</code></p>';
            }
        } else {
            echo '<p style="margin: 0; font-size: 13px; color: #666;">' . esc_html__('Bazinė linija (Lokalus diskas)', 'gratis-security') . '</p>';
        }
        echo '</div>';

        // 2. SIMDJSON Card
        echo '<div class="card" style="margin: 0; padding: 15px; border-left: 4px solid ' . ($caps['simdjson'] ? '#46b450' : '#999') . ';">';
        echo '<h3 style="margin: 0 0 5px 0;">' . esc_html__('SIMD-JSON akceleratorius', 'gratis-security') . '</h3>';
        if ($caps['simdjson']) {
            echo '<p style="margin: 0; font-size: 13px; color: #46b450; font-weight: 600;">✓ ' . esc_html__('Aktyvus (Be MySQL)', 'gratis-security') . '</p>';
            echo '<p style="margin: 3px 0 0; font-size: 12px; color: #666;">V: ' . esc_html((string) $caps['simdjson_version']) . '</p>';
        } else {
            echo '<p style="margin: 0; font-size: 13px; color: #666;">' . esc_html__('Native PHP fallback', 'gratis-security') . '</p>';
        }
        echo '</div>';

        // 3. Linux Kernel / Auditd Card
        $audit_ok = $caps['auditd_active'] || $caps['inotifywait'];
        echo '<div class="card" style="margin: 0; padding: 15px; border-left: 4px solid ' . ($audit_ok ? '#46b450' : '#2271b1') . ';">';
        echo '<h3 style="margin: 0 0 5px 0;">' . esc_html__('Serverio OS ir skydas', 'gratis-security') . '</h3>';
        echo '<p style="margin: 0; font-size: 12px; font-weight: 600;">' . esc_html($caps['os']) . '</p>';
        $shield_status = [];
        if ($caps['auditd_active']) {
            $shield_status[] = 'auditd (active)';
        }
        if ($caps['inotifywait']) {
            $shield_status[] = 'inotifywait';
        }
        if ($caps['aide']) {
            $shield_status[] = 'aide';
        }
        echo '<p style="margin: 3px 0 0; font-size: 12px; color: #666;">' . esc_html(implode(', ', $shield_status) ?: 'Standartinis') . '</p>';
        echo '</div>';

        // 4. Scan Summary Card
        $changed_total = $report ? ($report['modified_count'] + $report['missing_count'] + $report['untracked_count']) : 0;
        $card_color = ($changed_total > 0) ? '#d63638' : '#46b450';
        echo '<div class="card" style="margin: 0; padding: 15px; border-left: 4px solid ' . esc_attr($card_color) . ';">';
        echo '<h3 style="margin: 0 0 5px 0;">' . esc_html__('Failų būsena', 'gratis-security') . '</h3>';
        if ($report) {
            if ($changed_total > 0) {
                echo '<p style="margin: 0; font-size: 13px; color: #d63638; font-weight: 600;">⚠ ' . sprintf(/* translators: %d count */ esc_html__('Pakeitimų: %d', 'gratis-security'), $changed_total) . '</p>';
            } else {
                echo '<p style="margin: 0; font-size: 13px; color: #46b450; font-weight: 600;">✓ ' . esc_html__('Visi parašai sutampa', 'gratis-security') . '</p>';
            }
            echo '<p style="margin: 3px 0 0; font-size: 12px; color: #666;">' . esc_html(sprintf(/* translators: %d files */ __('Tikrinta: %d failų', 'gratis-security'), $report['total_checked'])) . '</p>';
        } else {
            echo '<p style="margin: 0; font-size: 13px; color: #666;">' . esc_html__('Patikra dar neatlikta', 'gratis-security') . '</p>';
        }
        echo '</div>';

        echo '</div>';

        // Actions toolbar
        echo '<div class="gratis-toolbar" style="display: flex; gap: 10px; align-items: center; margin-bottom: 20px; background: #fff; padding: 12px 16px; border: 1px solid #ccd0d4; border-radius: 4px;">';
        echo '<button type="button" id="gratis-scan-btn" class="button button-primary" style="display: inline-flex; align-items: center; gap: 6px;">';
        echo '<span class="dashicons dashicons-shield"></span> ' . esc_html__('Tikrinti failų parašus dabar', 'gratis-security');
        echo '</button>';
        echo '<button type="button" id="gratis-baseline-btn" class="button button-secondary">';
        echo esc_html__('Atnaujinti bazinę liniją (Baseline)', 'gratis-security');
        echo '</button>';
        echo '<span id="gratis-scan-spinner" class="spinner" style="float: none; margin: 0 10px;"></span>';
        echo '<span id="gratis-scan-msg" style="font-weight: 600; font-size: 13px;"></span>';

        if ($report && !empty($report['scanned_at'])) {
            echo '<span style="margin-left: auto; font-size: 12px; color: #666;">' . sprintf(/* translators: %s datetime */ esc_html__('Paskutinis nuskaitymas: %s', 'gratis-security'), esc_html($report['scanned_at'])) . '</span>';
        }
        echo '</div>';

        // Filters and Table
        self::render_fim_table($report);

        // Diff Modal Container
        self::render_diff_modal();

        // Enqueue inline JS for instant client-side filtering and AJAX
        self::render_fim_scripts();
    }

    /**
     * Render the interactive file table with client-side filtering.
     *
     * @param array<string,mixed>|null $report
     */
    private static function render_fim_table(?array $report): void {
        $files = $report['files'] ?? [];

        echo '<div class="gratis-table-container" style="background: #fff; border: 1px solid #ccd0d4; border-radius: 4px; padding: 16px;">';

        // Filter Controls
        echo '<div style="display: flex; flex-wrap: wrap; gap: 12px; justify-content: space-between; align-items: center; margin-bottom: 16px;">';
        echo '<div style="display: flex; gap: 8px; align-items: center;">';
        echo '<input type="search" id="gratis-search-input" placeholder="' . esc_attr__('Filtruoti pagal failą ar kelią...', 'gratis-security') . '" style="width: 280px; height: 32px;">';
        echo '<select id="gratis-component-filter" style="height: 32px;">';
        echo '<option value="">' . esc_html__('Visi komponentai', 'gratis-security') . '</option>';
        echo '<option value="core">' . esc_html__('WordPress Core', 'gratis-security') . '</option>';
        echo '<option value="mu-plugins">' . esc_html__('MU-Plugins', 'gratis-security') . '</option>';
        echo '<option value="plugins">' . esc_html__('Įskiepiai (Plugins)', 'gratis-security') . '</option>';
        echo '<option value="themes">' . esc_html__('Temos (Themes)', 'gratis-security') . '</option>';
        echo '<option value="vendor">' . esc_html__('Vendor paketai', 'gratis-security') . '</option>';
        echo '<option value="config">' . esc_html__('Konfigūracija', 'gratis-security') . '</option>';
        echo '</select>';
        echo '<select id="gratis-status-filter" style="height: 32px;">';
        echo '<option value="">' . esc_html__('Visos būsenos', 'gratis-security') . '</option>';
        echo '<option value="modified">' . esc_html__('Pakeisti (Modified)', 'gratis-security') . '</option>';
        echo '<option value="missing">' . esc_html__('Trūkstami (Missing)', 'gratis-security') . '</option>';
        echo '<option value="untracked">' . esc_html__('Nauji / Nežinomi (Untracked)', 'gratis-security') . '</option>';
        echo '</select>';
        echo '</div>';

        echo '<div style="font-size: 13px; color: #666;">';
        echo '<span id="gratis-filtered-count">' . count($files) . '</span> ' . esc_html__('failų sąraše', 'gratis-security');
        echo '</div>';
        echo '</div>';

        if (empty($files)) {
            echo '<div id="gratis-no-files" style="padding: 40px; text-align: center; color: #46b450;">';
            echo '<span class="dashicons dashicons-yes-alt" style="font-size: 48px; width: 48px; height: 48px; margin-bottom: 10px;"></span>';
            echo '<h3 style="margin: 0 0 5px 0;">' . esc_html__('Visi failai atitinka versijuotus parašus!', 'gratis-security') . '</h3>';
            echo '<p style="margin: 0; color: #666;">' . esc_html__('Jokių pakeitimų, trūkstamų ar nežinomų failų nerasta.', 'gratis-security') . '</p>';
            echo '</div>';
            echo '</div>';
            return;
        }

        echo '<table class="widefat striped" id="gratis-files-table">';
        echo '<thead><tr>';
        echo '<th>' . esc_html__('Failo kelias', 'gratis-security') . '</th>';
        echo '<th style="width: 130px;">' . esc_html__('Komponentas', 'gratis-security') . '</th>';
        echo '<th style="width: 110px;">' . esc_html__('Būsena', 'gratis-security') . '</th>';
        echo '<th style="width: 110px;">' . esc_html__('Dydis', 'gratis-security') . '</th>';
        echo '<th style="width: 150px;">' . esc_html__('Pakeistas', 'gratis-security') . '</th>';
        echo '<th style="width: 120px; text-align: right;">' . esc_html__('Veiksmai', 'gratis-security') . '</th>';
        echo '</tr></thead>';
        echo '<tbody>';

        foreach ($files as $file) {
            $path = (string) ($file['path'] ?? '');
            $component = (string) ($file['component'] ?? 'other');
            $status = (string) ($file['status'] ?? 'modified');
            $size = isset($file['size']) && $file['size'] > 0 ? size_format((int) $file['size'], 1) : '-';
            $mtime = (string) ($file['mtime'] ?? '-');

            $status_color = '#d63638';
            $status_label = __('Pakeistas', 'gratis-security');
            if ($status === 'missing') {
                $status_color = '#b32d2e';
                $status_label = __('Trūksta', 'gratis-security');
            } elseif ($status === 'untracked') {
                $status_color = '#2271b1';
                $status_label = __('Naujas', 'gratis-security');
            }

            echo '<tr class="gratis-file-row" data-path="' . esc_attr(strtolower($path)) . '" data-component="' . esc_attr($component) . '" data-status="' . esc_attr($status) . '">';
            echo '<td><code style="word-break: break-all;">' . esc_html($path) . '</code></td>';
            echo '<td><span class="badge" style="background:#f0f0f1; padding:3px 8px; border-radius:3px; font-size:11px;">' . esc_html($component) . '</span></td>';
            echo '<td><span style="display:inline-block; padding:3px 8px; border-radius:3px; font-size:11px; font-weight:600; color:#fff; background:' . esc_attr($status_color) . ';">' . esc_html($status_label) . '</span></td>';
            echo '<td>' . esc_html($size) . '</td>';
            echo '<td><span style="font-size:12px; color:#555;">' . esc_html($mtime) . '</span></td>';
            echo '<td style="text-align: right;">';
            if ($status !== 'missing') {
                echo '<button type="button" class="button button-small gratis-diff-btn" data-file="' . esc_attr($path) . '">';
                echo esc_html__('Diff / Krizė', 'gratis-security');
                echo '</button>';
            }
            echo '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';
        echo '</div>';
    }

    /**
     * Render the diff viewer modal.
     */
    private static function render_diff_modal(): void {
        echo '<div id="gratis-diff-modal" style="display:none; position:fixed; z-index:100000; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,0.6); align-items:center; justify-content:center;">';
        echo '<div style="background:#fff; width:85%; max-width:1000px; height:80%; max-height:700px; border-radius:6px; display:flex; flex-direction:column; box-shadow:0 10px 25px rgba(0,0,0,0.4); overflow:hidden;">';
        echo '<div style="padding:14px 20px; background:#f6f7f7; border-bottom:1px solid #dcdcde; display:flex; justify-content:space-between; align-items:center;">';
        echo '<div><h3 id="gratis-modal-title" style="margin:0; font-size:15px; font-family:monospace;"></h3><span id="gratis-modal-info" style="font-size:12px; color:#666;"></span></div>';
        echo '<button type="button" id="gratis-modal-close" class="button button-link" style="font-size:20px; text-decoration:none; color:#555;">&times;</button>';
        echo '</div>';
        echo '<div style="flex:1; overflow:auto; padding:16px; background:#1e1e1e; color:#d4d4d4; font-family:Consolas, Monaco, monospace; font-size:13px; line-height:1.5;">';
        echo '<pre id="gratis-modal-content" style="margin:0; white-space:pre-wrap; word-break:break-all;"></pre>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
    }

    /**
     * Render the General settings tab.
     */
    private static function render_general_tab(): void {
        $settings = self::all();
        $waf_mode = (string) ($settings['waf_mode'] ?? 'monitor');
        if (!in_array($waf_mode, ['off', 'monitor', 'block'], true)) {
            $waf_mode = !empty($settings['waf_enabled']) ? 'block' : 'monitor';
        }

        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('Bendrieji apsaugos nustatymai', 'gratis-security') . '</h2>';
        echo '<form method="post" action="options.php">';
        settings_fields(self::GROUP);
        echo '<input type="hidden" name="' . esc_attr(self::OPTION) . '[_general_form]" value="1">';
        echo '<table class="form-table" role="presentation"><tbody>';

        echo '<tr><th scope="row"><label for="gs_waf_mode">' . esc_html__('Užklausų tikrinimo ir WAF režimas', 'gratis-security') . '</label></th><td>';
        echo '<select id="gs_waf_mode" name="' . esc_attr(self::OPTION) . '[waf_mode]">';
        echo '<option value="off"' . selected($waf_mode, 'off', false) . '>' . esc_html__('Išjungta (off)', 'gratis-security') . '</option>';
        echo '<option value="monitor"' . selected($waf_mode, 'monitor', false) . '>' . esc_html__('Stebėti ir registruoti (monitor — saugus numatytasis)', 'gratis-security') . '</option>';
        echo '<option value="block"' . selected($waf_mode, 'block', false) . '>' . esc_html__('Aktyvus blokavimas (block)', 'gratis-security') . '</option>';
        echo '</select>';
        echo '<p class="description">' . esc_html__('Stebėjimo režimas tik fiksuoja įtartinas užklausas (SQLi, XSS, LFI, RCE, zondai) be klaidingų blokavimų.', 'gratis-security') . '</p>';
        echo '</td></tr>';

        self::checkbox_row($settings, 'auto_ban_enabled', __('Automatinis IP blokavimas (Auto-Ban)', 'gratis-security'), __('Laikinai užblokuoti IP adresus po pasikartojančių atakų ar 404 paieškų.', 'gratis-security'));

        echo '<tr><th scope="row"><label for="gs_ban_threshold">' . esc_html__('Auto-Ban slenkstis (pažeidimai)', 'gratis-security') . '</label></th><td>';
        echo '<input type="number" min="1" id="gs_ban_threshold" class="small-text" name="' . esc_attr(self::OPTION) . '[auto_ban_threshold]" value="' . esc_attr((string) (int) ($settings['auto_ban_threshold'] ?? 5)) . '">';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="gs_ban_minutes">' . esc_html__('Auto-Ban trukmė (minutėmis)', 'gratis-security') . '</label></th><td>';
        echo '<input type="number" min="1" id="gs_ban_minutes" class="small-text" name="' . esc_attr(self::OPTION) . '[auto_ban_minutes]" value="' . esc_attr((string) (int) ($settings['auto_ban_minutes'] ?? 60)) . '">';
        echo '</td></tr>';

        self::checkbox_row($settings, 'block_xmlrpc', __('Blokuoti XML-RPC', 'gratis-security'), __('Atmesti visas xmlrpc.php užklausas (dažnas brute-force taikinys).', 'gratis-security'));
        self::checkbox_row($settings, 'headers_enabled', __('Saugumo antraštės (Headers)', 'gratis-security'), __('Siųsti X-Frame-Options, X-Content-Type-Options, Referrer-Policy antraštes.', 'gratis-security'));

        echo '<tr><th scope="row"><label for="gs_csp">' . esc_html__('Content-Security-Policy', 'gratis-security') . '</label></th><td>';
        echo '<input type="text" id="gs_csp" class="large-text" name="' . esc_attr(self::OPTION) . '[csp]" value="' . esc_attr((string) ($settings['csp'] ?? '')) . '"> ';
        echo '<p class="description">' . esc_html__('Nebūtina. Palikite tuščią, jei nenaudojate CSP.', 'gratis-security') . '</p>';
        echo '</td></tr>';

        self::checkbox_row($settings, 'login_protection', __('Prisijungimo bandymų ribojimas', 'gratis-security'), __('Užrakinti IP po per didelio nesėkmingų prisijungimų skaičiaus.', 'gratis-security'));

        echo '<tr><th scope="row"><label for="gs_max_tries">' . esc_html__('Maksimalus bandymų skaičius', 'gratis-security') . '</label></th><td>';
        echo '<input type="number" min="1" id="gs_max_tries" class="small-text" name="' . esc_attr(self::OPTION) . '[login_max_tries]" value="' . esc_attr((string) (int) ($settings['login_max_tries'] ?? 5)) . '">';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="gs_lockout">' . esc_html__('Užrakinimo trukmė (minutėmis)', 'gratis-security') . '</label></th><td>';
        echo '<input type="number" min="1" id="gs_lockout" class="small-text" name="' . esc_attr(self::OPTION) . '[login_lockout]" value="' . esc_attr((string) (int) ($settings['login_lockout'] ?? 15)) . '">';
        echo '</td></tr>';

        self::checkbox_row($settings, 'integrity_enabled', __('Failų stebėjimas įjungtas (FIM)', 'gratis-security'), __('Tikrinti failų parašus pagal versijuotą manifestą ir WP Core.', 'gratis-security'));
        self::checkbox_row($settings, 'malware_auto_scan', __('Planinis kenkėjiško kodo skenavimas', 'gratis-security'), __('Kasdien vykdyti kenkėjiško kodo patikrą per WP-Cron.', 'gratis-security'));
        self::checkbox_row($settings, 'use_clamav', __('Naudoti ClamAV (jei įdiegtas)', 'gratis-security'), __('Papildomai skenuoti su serverio clamscan / clamdscan įrankiu.', 'gratis-security'));
        self::checkbox_row($settings, 'notify_email_on_fim', __('El. pašto įspėjimai apie FIM incidentus', 'gratis-security'), __('Siųsti el. laišką administratoriui aptikus neautorizuotus failų pakeitimus.', 'gratis-security'));
        self::checkbox_row($settings, 'notify_email_on_malware', __('El. pašto įspėjimai apie kenkėjišką kodą', 'gratis-security'), __('Siųsti el. laišką administratoriui aptikus kritinį ar aukšto sunkumo kodą.', 'gratis-security'));
        self::checkbox_row($settings, 'twofa_enabled', __('Dviejų faktorių autentifikacija (2FA)', 'gratis-security'), __('Reikalauti TOTP kodo administratoriams.', 'gratis-security'));

        echo '</tbody></table>';
        submit_button();
        echo '</form>';
        echo '</div>';
    }

    private static function checkbox_row(array $settings, string $key, string $label, string $description): void {
        echo '<tr><th scope="row">' . esc_html($label) . '</th><td>';
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION) . '[' . esc_attr($key) . ']" value="1"' . checked((int) ($settings[$key] ?? 0), 1, false) . '> ';
        echo esc_html($description) . '</label>';
        echo '</td></tr>';
    }

    private static function maybe_handle_actions(): void {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $action = isset($_POST['gratis_security_action']) ? sanitize_key(wp_unslash($_POST['gratis_security_action'])) : '';
        if ('' === $action || !current_user_can('manage_options')) {
            return;
        }
        check_admin_referer('gratis_security_action');

        if ('clear_blocks' === $action) {
            WAF::clear_blocks();
            add_settings_error('gratis_security', 'blocks', __('Blokavimų žurnalas išvalytas.', 'gratis-security'), 'success');
        }

        settings_errors('gratis_security');
    }

    /**
     * AJAX handler to run scan and return JSON.
     */
    public static function ajax_scan(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $report = FileIntegrity::scan();
        wp_send_json_success($report);
    }

    /**
     * AJAX handler to fetch file diff.
     */
    public static function ajax_diff(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $file = isset($_POST['file']) ? sanitize_text_field(wp_unslash($_POST['file'])) : '';
        if ('' === $file) {
            wp_send_json_error(['message' => 'Missing file parameter']);
        }

        $diff = FileIntegrity::get_file_diff($file);
        wp_send_json_success($diff);
    }

    /**
     * AJAX handler to rebuild local baseline.
     */
    public static function ajax_baseline(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $count = FileIntegrity::build_baseline();
        wp_send_json_success(['count' => $count]);
    }

    /**
     * AJAX handler to run live server diagnostic inspection.
     */
    public static function ajax_server_wizard(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $mode_raw = isset($_POST['service_user_mode']) ? sanitize_key(wp_unslash($_POST['service_user_mode'])) : 'php';
        $mode     = ('root' === $mode_raw) ? 'root' : 'php';
        wp_send_json_success(ServerInspector::inspect($mode));
    }

    /**
     * AJAX handler to trail configured event logs and return updated detections and recent events.
     */
    public static function ajax_fim_trail(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $per_page   = isset($_POST['per_page']) ? max(1, min(200, absint($_POST['per_page']))) : 20;
        $trail      = EventMonitor::trail();
        $detections = EventMonitor::query_detections(['page' => 1, 'per_page' => $per_page]);
        $events     = EventMonitor::query_events(['page' => 1, 'per_page' => $per_page]);

        wp_send_json_success([
            'trail'      => $trail,
            'detections' => $detections,
            'events'     => $events,
        ]);
    }

    /**
     * AJAX handler to filter and return recent raw event logs.
     */
    public static function ajax_fim_logs(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $filters = [
            'search'          => isset($_POST['search']) ? sanitize_text_field(wp_unslash($_POST['search'])) : '',
            'event'           => isset($_POST['event']) ? sanitize_text_field(wp_unslash($_POST['event'])) : '',
            'component'       => isset($_POST['component']) ? sanitize_key(wp_unslash($_POST['component'])) : '',
            'source'          => isset($_POST['source']) ? sanitize_key(wp_unslash($_POST['source'])) : '',
            'since'           => isset($_POST['since']) ? sanitize_key(wp_unslash($_POST['since'])) : 'all',
            'only_suspicious' => !empty($_POST['only_suspicious']) && 'false' !== $_POST['only_suspicious'] && '0' !== $_POST['only_suspicious'],
            'page'            => isset($_POST['page']) ? max(1, absint($_POST['page'])) : 1,
            'per_page'        => isset($_POST['per_page']) ? max(1, min(500, absint($_POST['per_page']))) : 20,
        ];
        if (isset($_POST['limit'])) {
            $filters['limit'] = max(1, min(500, absint($_POST['limit'])));
        }

        wp_send_json_success(EventMonitor::query_events($filters));
    }

    /**
     * AJAX handler to list, update status, bulk update, purge verified, or clear persisted detections.
     */
    public static function ajax_fim_detections(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $subaction = isset($_POST['subaction']) ? sanitize_key(wp_unslash($_POST['subaction'])) : 'list';
        if (!in_array($subaction, ['list', 'update_status', 'bulk_status', 'purge_verified', 'clear'], true)) {
            $subaction = 'list';
        }

        $filters = [
            'search'    => isset($_POST['search']) ? sanitize_text_field(wp_unslash($_POST['search'])) : '',
            'severity'  => isset($_POST['severity']) ? sanitize_key(wp_unslash($_POST['severity'])) : '',
            'status'    => isset($_POST['filter_status'])
                ? sanitize_key(wp_unslash($_POST['filter_status']))
                : (('list' === $subaction && isset($_POST['status'])) ? sanitize_key(wp_unslash($_POST['status'])) : ''),
            'component' => isset($_POST['component']) ? sanitize_key(wp_unslash($_POST['component'])) : '',
            'page'      => isset($_POST['page']) ? max(1, absint($_POST['page'])) : 1,
            'per_page'  => isset($_POST['per_page']) ? max(1, min(500, absint($_POST['per_page']))) : 20,
        ];
        if (isset($_POST['limit'])) {
            $filters['limit'] = max(1, min(500, absint($_POST['limit'])));
        }

        if ('update_status' === $subaction) {
            $id     = isset($_POST['id']) ? sanitize_text_field(wp_unslash($_POST['id'])) : '';
            $status = isset($_POST['status']) ? sanitize_key(wp_unslash($_POST['status'])) : '';
            if (!in_array($status, ['open', 'acknowledged', 'resolved'], true) || '' === $id || !EventMonitor::update_detection_status($id, $status)) {
                wp_send_json_error(['message' => __('Nepavyko atnaujinti incidento būsenos.', 'gratis-security')]);
            }
            wp_send_json_success(EventMonitor::query_detections($filters));
        }

        if ('bulk_status' === $subaction) {
            $new_status = isset($_POST['new_status']) ? sanitize_key(wp_unslash($_POST['new_status'])) : 'acknowledged';
            if (!in_array($new_status, ['open', 'acknowledged', 'resolved'], true)) {
                wp_send_json_error(['message' => __('Neteisinga būsena.', 'gratis-security')], 400);
            }
            $updated = EventMonitor::bulk_update_status($filters, $new_status);
            wp_send_json_success(array_merge(['updated' => $updated], EventMonitor::query_detections($filters)));
        }

        if ('purge_verified' === $subaction) {
            $purge = EventMonitor::purge_verified_detections();
            wp_send_json_success(array_merge($purge, EventMonitor::query_detections($filters)));
        }

        if ('clear' === $subaction) {
            $clear_status = isset($_POST['clear_status']) ? sanitize_key(wp_unslash($_POST['clear_status'])) : 'resolved';
            if (!in_array($clear_status, ['resolved', 'acknowledged', 'all'], true)) {
                $clear_status = 'resolved';
            }
            $removed = EventMonitor::clear_detections($clear_status);
            wp_send_json_success(array_merge(['removed' => $removed], EventMonitor::query_detections($filters)));
        }

        wp_send_json_success(EventMonitor::query_detections($filters));
    }

    /**
     * AJAX handler to return full SetupWizard diagnostic posture.
     */
    public static function ajax_wizard_diagnose(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $mode_raw = isset($_POST['service_user_mode']) ? sanitize_key(wp_unslash($_POST['service_user_mode'])) : 'php';
        $mode     = ('root' === $mode_raw) ? 'root' : 'php';
        wp_send_json_success(SetupWizard::diagnose($mode));
    }

    /**
     * AJAX handler to run 1-click PHP-only security auto-configuration.
     */
    public static function ajax_wizard_autoconfig(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $waf_mode_raw = isset($_POST['waf_mode']) ? sanitize_key(wp_unslash($_POST['waf_mode'])) : 'monitor';
        $waf_mode     = in_array($waf_mode_raw, ['monitor', 'block', 'off'], true) ? $waf_mode_raw : 'monitor';
        $sync_wp      = !isset($_POST['sync_wp_checksums']) || ('0' !== $_POST['sync_wp_checksums'] && 'false' !== $_POST['sync_wp_checksums']);
        $run_scans    = !isset($_POST['run_scans']) || ('0' !== $_POST['run_scans'] && 'false' !== $_POST['run_scans']);

        $res = SetupWizard::run_auto_configure([
            'waf_mode'          => $waf_mode,
            'sync_wp_checksums' => $sync_wp,
            'run_scans'         => $run_scans,
        ]);
        wp_send_json_success($res);
    }

    /**
     * AJAX handler to run an on-demand malware scan.
     */
    public static function ajax_malware_scan(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $deep       = !empty($_POST['deep']) && '0' !== $_POST['deep'] && 'false' !== $_POST['deep'];
        $use_clamav = !empty($_POST['use_clamav']) && '0' !== $_POST['use_clamav'] && 'false' !== $_POST['use_clamav'];

        $report = MalwareScanner::scan(null, [
            'deep'       => $deep,
            'use_clamav' => $use_clamav,
        ]);
        wp_send_json_success($report);
    }

    /**
     * AJAX handler for quarantine, restore, delete, and whitelist actions.
     */
    public static function ajax_malware_action(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $subaction = isset($_POST['subaction']) ? sanitize_key(wp_unslash($_POST['subaction'])) : '';
        if (!in_array($subaction, ['quarantine', 'restore', 'delete_quarantine', 'whitelist', 'remove_whitelist'], true)) {
            wp_send_json_error(['message' => __('Nežinomas veiksmas.', 'gratis-security')], 400);
        }

        $file   = isset($_POST['file']) ? sanitize_text_field(wp_unslash($_POST['file'])) : '';
        $id     = isset($_POST['id']) ? sanitize_text_field(wp_unslash($_POST['id'])) : '';
        $reason = isset($_POST['reason']) ? sanitize_text_field(wp_unslash($_POST['reason'])) : '';
        $msg    = '';

        if ('quarantine' === $subaction) {
            $res = MalwareScanner::quarantine_file($file, null, null, $reason);
            if (empty($res['success'])) {
                wp_send_json_error(['message' => (string) ($res['error'] ?? 'Quarantine failed')]);
            }
            $msg = __('Failas perkeltas į karantiną.', 'gratis-security');
        } elseif ('restore' === $subaction) {
            $res = MalwareScanner::restore_quarantine($id);
            if (empty($res['success'])) {
                wp_send_json_error(['message' => (string) ($res['error'] ?? 'Restore failed')]);
            }
            $msg = __('Failas atkurtas iš karantino.', 'gratis-security');
        } elseif ('delete_quarantine' === $subaction) {
            $res = MalwareScanner::delete_quarantine($id);
            if (empty($res['success'])) {
                wp_send_json_error(['message' => (string) ($res['error'] ?? 'Delete failed')]);
            }
            $msg = __('Failas visam laikui ištrintas.', 'gratis-security');
        } elseif ('whitelist' === $subaction) {
            $res = MalwareScanner::whitelist_file($file);
            if (empty($res['success'])) {
                wp_send_json_error(['message' => (string) ($res['error'] ?? 'Whitelist failed')]);
            }
            $msg = __('Failas pridėtas į baltąjį sąrašą.', 'gratis-security');
        } else {
            if (!MalwareScanner::remove_whitelist($file)) {
                wp_send_json_error(['message' => __('Failas nerastas baltajame sąraše.', 'gratis-security')]);
            }
            $msg = __('Failas pašalintas iš baltojo sąrašo.', 'gratis-security');
        }

        $report   = MalwareScanner::get_last_report();
        $findings = is_array($report) ? (array) ($report['findings'] ?? []) : [];
        if (in_array($subaction, ['quarantine', 'whitelist'], true) && '' !== $file) {
            $norm_target = ltrim(str_replace('\\', '/', $file), '/');
            $findings    = array_values(array_filter(
                $findings,
                static fn(array $f): bool => ltrim(str_replace('\\', '/', (string) ($f['file'] ?? '')), '/') !== $norm_target
            ));
        }

        wp_send_json_success([
            'message'    => $msg,
            'quarantine' => MalwareScanner::list_quarantine(),
            'whitelist'  => (object) MalwareScanner::get_whitelist(),
            'findings'   => $findings,
        ]);
    }

    /**
     * AJAX handler to query paginated malicious requests.
     */
    public static function ajax_requests_query(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $filters = [
            'search'   => isset($_POST['search']) ? sanitize_text_field(wp_unslash($_POST['search'])) : '',
            'category' => isset($_POST['category']) ? sanitize_key(wp_unslash($_POST['category'])) : 'all',
            'severity' => isset($_POST['severity']) ? sanitize_key(wp_unslash($_POST['severity'])) : 'all',
            'action'   => isset($_POST['action_filter']) ? sanitize_key(wp_unslash($_POST['action_filter'])) : 'all',
            'since'    => isset($_POST['since']) ? sanitize_key(wp_unslash($_POST['since'])) : 'all',
            'page'     => isset($_POST['page']) ? max(1, absint($_POST['page'])) : 1,
            'per_page' => isset($_POST['per_page']) ? max(1, min(200, absint($_POST['per_page']))) : 25,
        ];

        wp_send_json_success(RequestGuard::query_requests($filters));
    }

    /**
     * AJAX handler to manage IP blocklist, allowlist, active bans, and request logs.
     */
    public static function ajax_requests_ip(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $subaction = isset($_POST['subaction']) ? sanitize_key(wp_unslash($_POST['subaction'])) : '';
        if (!in_array($subaction, ['block', 'allow', 'remove_rule', 'unban', 'clear_logs'], true)) {
            wp_send_json_error(['message' => __('Nežinomas veiksmas.', 'gratis-security')], 400);
        }

        $ip   = isset($_POST['ip']) ? trim(sanitize_text_field(wp_unslash($_POST['ip']))) : '';
        $note = isset($_POST['note']) ? sanitize_text_field(wp_unslash($_POST['note'])) : '';
        $msg  = '';

        if ('block' === $subaction) {
            $res = RequestGuard::add_ip_rule($ip, 'blocklist', $note);
            if (empty($res['success'])) {
                wp_send_json_error(['message' => (string) ($res['error'] ?? 'Invalid IP/CIDR')]);
            }
            $msg = __('IP pridėtas į blokavimo sąrašą.', 'gratis-security');
        } elseif ('allow' === $subaction) {
            $res = RequestGuard::add_ip_rule($ip, 'allowlist', $note);
            if (empty($res['success'])) {
                wp_send_json_error(['message' => (string) ($res['error'] ?? 'Invalid IP/CIDR')]);
            }
            $msg = __('IP pridėtas į leistinų sąrašą.', 'gratis-security');
        } elseif ('remove_rule' === $subaction) {
            $list = isset($_POST['list']) ? sanitize_key(wp_unslash($_POST['list'])) : '';
            if (!in_array($list, ['blocklist', 'allowlist'], true) || !RequestGuard::remove_ip_rule($ip, $list)) {
                wp_send_json_error(['message' => __('IP taisyklė nerasta.', 'gratis-security')]);
            }
            $msg = __('IP taisyklė pašalinta.', 'gratis-security');
        } elseif ('unban' === $subaction) {
            if (!RequestGuard::unban_ip($ip)) {
                wp_send_json_error(['message' => __('Aktyvus banas šiam IP nerastas.', 'gratis-security')]);
            }
            $msg = __('IP atblokuotas.', 'gratis-security');
        } else {
            RequestGuard::clear_requests();
            $msg = __('Užklausų žurnalas išvalytas.', 'gratis-security');
        }

        wp_send_json_success([
            'message' => $msg,
            'rules'   => RequestGuard::get_ip_rules(),
            'bans'    => array_values(RequestGuard::get_active_bans()),
        ]);
    }

    /**
     * AJAX handler to update threat signatures and WP core checksums.
     */
    public static function ajax_signatures_update(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        wp_send_json_success(SignatureFeed::update());
    }

    /**
     * AJAX handler to persist signature & IP feed subscription settings.
     */
    public static function ajax_signatures_save_feeds(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $feed_url    = isset($_POST['signature_feed_url']) ? trim((string) wp_unslash($_POST['signature_feed_url'])) : '';
        $ip_feed_url = isset($_POST['ip_feed_url']) ? trim((string) wp_unslash($_POST['ip_feed_url'])) : '';
        $token       = isset($_POST['signature_feed_token']) ? sanitize_text_field(trim((string) wp_unslash($_POST['signature_feed_token']))) : '';

        foreach (['signature_feed_url' => $feed_url, 'ip_feed_url' => $ip_feed_url] as $label => $u) {
            if ('' !== $u) {
                $clean = esc_url_raw($u, ['https']);
                if ('' === $clean || !str_starts_with(strtolower($clean), 'https://')) {
                    wp_send_json_error(['message' => sprintf(__('%s privalo prasidėti https://', 'gratis-security'), $label)], 400);
                }
            }
        }

        $current = self::all();
        $merged  = array_merge($current, [
            'signature_auto_update' => (!isset($_POST['signature_auto_update']) || ('0' !== $_POST['signature_auto_update'] && 'false' !== $_POST['signature_auto_update'])) ? 1 : 0,
            'sync_wp_checksums'     => (!isset($_POST['sync_wp_checksums']) || ('0' !== $_POST['sync_wp_checksums'] && 'false' !== $_POST['sync_wp_checksums'])) ? 1 : 0,
            'signature_feed_url'    => '' !== $feed_url ? esc_url_raw($feed_url, ['https']) : '',
            'signature_feed_token'  => $token,
            'ip_feed_url'           => '' !== $ip_feed_url ? esc_url_raw($ip_feed_url, ['https']) : '',
        ]);

        update_option(self::OPTION, $merged);

        wp_send_json_success([
            'saved'    => true,
            'settings' => self::all(),
        ]);
    }

    /**
     * Inline script for fast filtering, AJAX scan, and diff modal.
     */
    private static function render_fim_scripts(): void {
        $nonce = wp_create_nonce('gratis_fim_nonce');
        ?>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var searchInput = document.getElementById('gratis-search-input');
            var compFilter = document.getElementById('gratis-component-filter');
            var statusFilter = document.getElementById('gratis-status-filter');
            var rows = document.querySelectorAll('.gratis-file-row');
            var countEl = document.getElementById('gratis-filtered-count');

            function filterRows() {
                var search = searchInput ? searchInput.value.toLowerCase().trim() : '';
                var comp = compFilter ? compFilter.value : '';
                var stat = statusFilter ? statusFilter.value : '';
                var visibleCount = 0;

                rows.forEach(function(row) {
                    var path = row.getAttribute('data-path') || '';
                    var rComp = row.getAttribute('data-component') || '';
                    var rStat = row.getAttribute('data-status') || '';

                    var matchSearch = !search || path.indexOf(search) !== -1;
                    var matchComp = !comp || rComp === comp;
                    var matchStat = !stat || rStat === stat;

                    if (matchSearch && matchComp && matchStat) {
                        row.style.display = '';
                        visibleCount++;
                    } else {
                        row.style.display = 'none';
                    }
                });

                if (countEl) {
                    countEl.textContent = visibleCount;
                }
            }

            if (searchInput) searchInput.addEventListener('input', filterRows);
            if (compFilter) compFilter.addEventListener('change', filterRows);
            if (statusFilter) statusFilter.addEventListener('change', filterRows);

            // AJAX Scan
            var scanBtn = document.getElementById('gratis-scan-btn');
            var baselineBtn = document.getElementById('gratis-baseline-btn');
            var spinner = document.getElementById('gratis-scan-spinner');
            var msg = document.getElementById('gratis-scan-msg');

            if (scanBtn) {
                scanBtn.addEventListener('click', function() {
                    scanBtn.disabled = true;
                    if (spinner) spinner.classList.add('is-active');
                    if (msg) {
                        msg.style.color = '#2271b1';
                        msg.textContent = '<?php echo esc_js(__('Tikrinami parašai...', 'gratis-security')); ?>';
                    }

                    var formData = new FormData();
                    formData.append('action', 'gratis_fim_scan');
                    formData.append('nonce', '<?php echo esc_js($nonce); ?>');

                    fetch(ajaxurl, {
                        method: 'POST',
                        body: formData
                    })
                    .then(function(res) { return res.json(); })
                    .then(function(data) {
                        scanBtn.disabled = false;
                        if (spinner) spinner.classList.remove('is-active');
                        if (data.success) {
                            if (msg) {
                                msg.style.color = '#46b450';
                                msg.textContent = '<?php echo esc_js(__('Patikra baigta! Perkraunama...', 'gratis-security')); ?>';
                            }
                            setTimeout(function() { window.location.reload(); }, 600);
                        } else {
                            if (msg) {
                                msg.style.color = '#d63638';
                                msg.textContent = data.data && data.data.message ? data.data.message : 'Klaida';
                            }
                        }
                    })
                    .catch(function(err) {
                        scanBtn.disabled = false;
                        if (spinner) spinner.classList.remove('is-active');
                        if (msg) {
                            msg.style.color = '#d63638';
                            msg.textContent = 'Ryšio klaida';
                        }
                    });
                });
            }

            if (baselineBtn) {
                baselineBtn.addEventListener('click', function() {
                    if (!confirm('<?php echo esc_js(__('Ar tikrai norite atnaujinti bazinę liniją pagal dabartinius failus?', 'gratis-security')); ?>')) {
                        return;
                    }
                    baselineBtn.disabled = true;
                    if (spinner) spinner.classList.add('is-active');

                    var formData = new FormData();
                    formData.append('action', 'gratis_fim_baseline');
                    formData.append('nonce', '<?php echo esc_js($nonce); ?>');

                    fetch(ajaxurl, {
                        method: 'POST',
                        body: formData
                    })
                    .then(function(res) { return res.json(); })
                    .then(function(data) {
                        baselineBtn.disabled = false;
                        if (spinner) spinner.classList.remove('is-active');
                        if (data.success) {
                            alert('Bazinė linija išsaugota (' + data.data.count + ' failų)');
                            window.location.reload();
                        }
                    });
                });
            }

            // Diff Modal
            var modal = document.getElementById('gratis-diff-modal');
            var modalClose = document.getElementById('gratis-modal-close');
            var modalTitle = document.getElementById('gratis-modal-title');
            var modalInfo = document.getElementById('gratis-modal-info');
            var modalContent = document.getElementById('gratis-modal-content');

            document.querySelectorAll('.gratis-diff-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    var file = btn.getAttribute('data-file');
                    if (!file) return;

                    modalTitle.textContent = file;
                    modalInfo.textContent = 'Kraunama...';
                    modalContent.textContent = 'Kraunami kodo skirtumai...';
                    modal.style.display = 'flex';

                    var formData = new FormData();
                    formData.append('action', 'gratis_fim_diff');
                    formData.append('nonce', '<?php echo esc_js($nonce); ?>');
                    formData.append('file', file);

                    fetch(ajaxurl, {
                        method: 'POST',
                        body: formData
                    })
                    .then(function(res) { return res.json(); })
                    .then(function(data) {
                        if (data.success && data.data) {
                            modalInfo.textContent = data.data.info || '';
                            modalContent.textContent = data.data.diff || 'Pakeitimų nerasta';
                        } else {
                            modalInfo.textContent = 'Klaida';
                            modalContent.textContent = 'Nepavyko nuskaityti diff.';
                        }
                    })
                    .catch(function() {
                        modalInfo.textContent = 'Klaida';
                        modalContent.textContent = 'Nepavyko susisiekti su serveriu.';
                    });
                });
            });

            if (modalClose) {
                modalClose.addEventListener('click', function() {
                    modal.style.display = 'none';
                });
            }
            if (modal) {
                modal.addEventListener('click', function(e) {
                    if (e.target === modal) {
                        modal.style.display = 'none';
                    }
                });
            }
        });
        </script>
        <?php
    }
}
