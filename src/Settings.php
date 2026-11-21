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
            'waf_enabled'       => 0,
            'block_xmlrpc'      => 1,
            'headers_enabled'   => 1,
            'csp'               => '',
            'login_protection'  => 1,
            'login_max_tries'   => 5,
            'login_lockout'     => 15,
            'integrity_enabled' => 1,
            'twofa_enabled'     => 0,
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
    }

    /**
     * Sanitise incoming settings.
     *
     * @param mixed $input
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
     * Render the admin page with navigation tabs.
     */
    public static function render_page(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'gratis-security'));
        }

        self::maybe_handle_actions();

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $tab = isset($_GET['tab']) ? sanitize_key((string) $_GET['tab']) : 'fim';
        if (!in_array($tab, ['fim', 'server', 'general', 'blocks'], true)) {
            $tab = 'fim';
        }

        echo '<div class="wrap gratis-security-wrap">';
        echo '<h1>' . esc_html__('Gratis Security', 'gratis-security') . '</h1>';
        echo '<p class="description">' . esc_html__('Aukšto našumo serverio lygio failų stebėjimas, parašų patikra be MySQL apkrovos ir ugniasienė.', 'gratis-security') . '</p>';

        self::render_tabs($tab);

        switch ($tab) {
            case 'fim':
                self::render_fim_tab();
                break;
            case 'server':
                self::render_server_tab();
                break;
            case 'blocks':
                self::render_block_log();
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
            'fim'     => __('Failų stebėjimas ir parašai', 'gratis-security'),
            'server'  => __('Serverio integracija (Red Hat / Linux)', 'gratis-security'),
            'general' => __('Bendra apsauga (WAF, 2FA)', 'gratis-security'),
            'blocks'  => __('Blokuotų užklausų žurnalas', 'gratis-security'),
        ];

        echo '<nav class="nav-tab-wrapper" style="margin-bottom: 20px;">';
        foreach ($tabs as $key => $label) {
            $url = admin_url('options-general.php?page=' . self::PAGE . '&tab=' . $key);
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
     * Render the Server integration tab with live diagnostic wizard, detections store, and log trail UI.
     */
    private static function render_server_tab(): void {
        $inspection      = ServerInspector::inspect('php');
        $detections_data = EventMonitor::query_detections(['limit' => 100]);
        $events_data     = EventMonitor::query_events(['limit' => 100]);
        $trail_state     = EventMonitor::get_trail_state();

        $summary   = (array) ($inspection['summary'] ?? []);
        $runtime   = (array) ($inspection['runtime'] ?? []);
        $os        = (array) ($inspection['os'] ?? []);
        $tools     = (array) ($inspection['tools'] ?? []);
        $processes = (array) ($inspection['processes'] ?? []);
        $checks    = (array) ($inspection['checks'] ?? []);
        $recs      = (array) ($inspection['recommendations'] ?? []);
        $steps     = (array) ($recs['steps'] ?? []);

        $overall = (string) ($summary['overall'] ?? 'warn');
        [$overall_color, $overall_label] = match ($overall) {
            'ok'          => ['#46b450', __('Paruošta', 'gratis-security')],
            'needs_setup' => ['#d63638', __('Reikia sąrankos', 'gratis-security')],
            default       => ['#dba617', __('Dalinė sąranka', 'gratis-security')],
        };

        $tier = (string) ($recs['tier'] ?? 'autonomous_php');
        $tier_label = match ($tier) {
            'kernel_and_realtime' => 'kernel_and_realtime',
            'realtime_only'       => 'realtime_only',
            default               => 'autonomous_php',
        };

        $runtime_user  = (string) ($runtime['user'] ?? 'unknown');
        $runtime_group = (string) ($runtime['group'] ?? 'unknown');

        echo '<div style="max-width: 1150px; margin-top: 10px;">';

        // Card 1: Server Diagnostic Wizard
        echo '<div class="card" style="max-width: 1150px; padding: 20px; margin-bottom: 20px;">';
        echo '<div style="display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:12px; margin-bottom:14px;">';
        echo '<div>';
        echo '<h2 style="margin:0 0 4px 0;">' . esc_html__('Serverio diagnostikos vedlys', 'gratis-security') . '</h2>';
        echo '<span style="font-size:12px; color:#666;">' . esc_html__('Tikrinta:', 'gratis-security') . ' <span id="gratis-wizard-checked-at">' . esc_html((string) ($inspection['checked_at'] ?? '')) . '</span></span>';
        echo '</div>';
        echo '<div style="display:flex; align-items:center; gap:8px;">';
        echo '<span id="gratis-wizard-spinner" class="spinner" style="float:none; margin:0;"></span>';
        echo '<button type="button" id="gratis-wizard-run-btn" class="button button-primary">' . esc_html__('Paleisti diagnostiką', 'gratis-security') . '</button>';
        echo '</div>';
        echo '</div>';

        // Summary header bar
        echo '<div style="display:flex; flex-wrap:wrap; gap:12px; align-items:center; background:#f6f7f7; border:1px solid #dcdcde; border-radius:4px; padding:12px 14px; margin-bottom:18px; font-size:13px;">';
        echo '<span id="gratis-wizard-overall-badge" style="display:inline-block; padding:3px 10px; border-radius:3px; color:#fff; font-weight:600; background:' . esc_attr($overall_color) . ';">' . esc_html($overall_label) . '</span>';
        echo '<span><strong>' . esc_html__('Patikros:', 'gratis-security') . '</strong> <span id="gratis-wizard-passed-count">' . esc_html((string) ($summary['passed'] ?? 0) . ' / ' . (string) ($summary['total'] ?? 0)) . '</span></span>';
        echo '<span><strong>' . esc_html__('OS:', 'gratis-security') . '</strong> <span id="gratis-wizard-os-meta">' . esc_html((string) ($os['pretty_name'] ?? '') . ' (' . (string) ($os['machine'] ?? '') . ' / ' . (string) ($os['audit_arch'] ?? '') . ')') . '</span></span>';
        echo '<span><strong>' . esc_html__('PHP:', 'gratis-security') . '</strong> <code id="gratis-wizard-runtime-meta">' . esc_html($runtime_user . ':' . $runtime_group) . '</code></span>';
        echo '<span><strong>SELinux:</strong> <code id="gratis-wizard-selinux-meta">' . esc_html((string) ($runtime['selinux'] ?? 'unknown')) . '</code></span>';
        echo '<span><strong>Init:</strong> <code id="gratis-wizard-init-meta">' . esc_html((string) ($os['init_system'] ?? 'none')) . '</code></span>';
        echo '<span><strong>' . esc_html__('Režimas:', 'gratis-security') . '</strong> <code id="gratis-wizard-tier-meta">' . esc_html($tier_label) . '</code></span>';
        echo '</div>';

        // Live Diagnostic Matrix
        echo '<h3 style="margin:0 0 8px 0;">' . esc_html__('Patikrų suvestinė', 'gratis-security') . '</h3>';
        echo '<table class="widefat striped" style="margin-bottom:18px;">';
        echo '<thead><tr><th style="width:140px;">' . esc_html__('Būsena', 'gratis-security') . '</th><th style="width:230px;">' . esc_html__('Patikra', 'gratis-security') . '</th><th>' . esc_html__('Išsami informacija', 'gratis-security') . '</th></tr></thead>';
        echo '<tbody id="gratis-wizard-checks-body">';
        foreach ($checks as $chk) {
            [$badge_bg, $badge_txt] = self::wizard_check_badge((string) ($chk['status'] ?? 'missing'));
            echo '<tr>';
            echo '<td><span style="display:inline-block; padding:2px 8px; border-radius:3px; font-size:11px; font-weight:600; color:#fff; background:' . esc_attr($badge_bg) . ';">' . esc_html($badge_txt) . '</span></td>';
            echo '<td><strong>' . esc_html((string) ($chk['label'] ?? '')) . '</strong></td>';
            echo '<td><code>' . esc_html((string) ($chk['detail'] ?? '')) . '</code></td>';
            echo '</tr>';
        }
        echo '</tbody></table>';

        // Detected processes & tools bar
        echo '<h3 style="margin:0 0 8px 0;">' . esc_html__('Aptikti procesai ir įrankiai', 'gratis-security') . '</h3>';
        echo '<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:12px; margin-bottom:20px;">';

        echo '<div style="background:#f9f9f9; border:1px solid #dcdcde; border-radius:4px; padding:12px;">';
        echo '<div style="font-weight:600; margin-bottom:6px;">' . esc_html__('Veikiantys inotifywait procesai', 'gratis-security') . '</div>';
        echo '<div id="gratis-wizard-processes" style="font-size:12px;">';
        if (empty($processes)) {
            echo '<span style="color:#666;">' . esc_html__('Veikiančių inotifywait procesų neaptikta', 'gratis-security') . '</span>';
        } else {
            foreach ($processes as $proc) {
                $match_ok = !empty($proc['matches_web_dir']);
                echo '<div style="margin-bottom:4px;">';
                echo '<code>PID ' . esc_html((string) ($proc['pid'] ?? '')) . '</code> (' . esc_html((string) ($proc['user'] ?? '')) . ') ';
                echo '<span style="display:inline-block; padding:1px 6px; border-radius:3px; color:#fff; font-size:11px; background:' . ($match_ok ? '#46b450' : '#dba617') . ';">';
                echo esc_html($match_ok ? __('Kelias sutampa', 'gratis-security') : __('Kitas kelias', 'gratis-security'));
                echo '</span></div>';
            }
        }
        echo '</div></div>';

        echo '<div style="background:#f9f9f9; border:1px solid #dcdcde; border-radius:4px; padding:12px;">';
        echo '<div style="font-weight:600; margin-bottom:6px;">' . esc_html__('Įrankių prieinamumas', 'gratis-security') . '</div>';
        echo '<div id="gratis-wizard-tools" style="display:flex; flex-wrap:wrap; gap:6px; font-size:12px;">';
        $tool_keys = ['auditctl', 'augenrules', 'inotifywait', 'systemctl', 'wp', 'aide', 'git'];
        foreach ($tool_keys as $tkey) {
            $avail = !empty($tools[$tkey]['available']);
            echo '<span style="padding:2px 8px; border-radius:3px; color:#fff; background:' . ($avail ? '#46b450' : '#8c8f94') . ';">' . esc_html($tkey . ': ' . ($avail ? 'OK' : '—')) . '</span>';
        }
        $has_simd = function_exists('simdjson_decode');
        echo '<span style="padding:2px 8px; border-radius:3px; color:#fff; background:' . ($has_simd ? '#46b450' : '#8c8f94') . ';">' . esc_html('simdjson: ' . ($has_simd ? 'OK' : 'fallback')) . '</span>';
        $pkg_name = (string) ($tools['pkg_manager']['name'] ?? '');
        echo '<span style="padding:2px 8px; border-radius:3px; background:#e5e5e5; color:#1d2327;">' . esc_html('pkg: ' . ('' !== $pkg_name ? $pkg_name : 'nėra')) . '</span>';
        echo '</div></div>';

        echo '</div>';

        // Recommended modern configuration (Wizard Steps)
        echo '<h3 style="margin:0 0 8px 0;">' . esc_html__('Rekomenduojama moderni konfigūracija', 'gratis-security') . '</h3>';
        echo '<div style="display:flex; flex-wrap:wrap; align-items:center; gap:10px; margin-bottom:8px;">';
        echo '<label for="gratis-service-user-mode" style="font-weight:600;">' . esc_html__('Serviso vartotojas:', 'gratis-security') . '</label>';
        echo '<select id="gratis-service-user-mode" style="min-width:420px; max-width:100%;">';
        echo '<option value="php" selected>' . esc_html(sprintf('PHP vartotojas (%s:%s) — rekomenduojama (mažiausios teisės, rašo į įskiepio saugyklą)', $runtime_user, $runtime_group)) . '</option>';
        echo '<option value="root">' . esc_html__('root — tik skaitymui PHP (/var/log/gratis-fim.jsonl, atsparesnis pakeitimams)', 'gratis-security') . '</option>';
        echo '</select>';
        echo '</div>';
        echo '<p class="description" style="margin:0 0 14px 0;">' . esc_html__('Pastaba: Linux branduolio auditd visada veikia kaip root (PHP negali jo išjungti ar suklastoti žurnalų), tuo tarpu gratis-fim.service (inotifywait) ir wp cron saugiai veikia PHP vartotojo teisėmis.', 'gratis-security') . '</p>';

        echo '<div id="gratis-wizard-steps" style="display:flex; flex-direction:column; gap:12px; margin-bottom:14px;">';
        foreach ($steps as $idx => $step) {
            [$step_bg, $step_label] = self::wizard_step_badge((string) ($step['status'] ?? 'optional'));
            $cmd = (string) ($step['command'] ?? '');
            echo '<div style="border:1px solid #dcdcde; border-left:4px solid ' . esc_attr($step_bg) . '; border-radius:4px; padding:12px 14px; background:#fff;">';
            echo '<div style="display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:4px;">';
            echo '<strong>' . esc_html(($idx + 1) . '. ' . (string) ($step['title'] ?? '')) . '</strong>';
            echo '<span style="display:inline-block; padding:2px 8px; border-radius:3px; font-size:11px; font-weight:600; color:#fff; background:' . esc_attr($step_bg) . ';">' . esc_html($step_label) . '</span>';
            echo '</div>';
            if (!empty($step['reason'])) {
                echo '<p style="margin:2px 0 6px 0; font-size:13px;">' . esc_html((string) $step['reason']) . '</p>';
            }
            if (!empty($step['note'])) {
                echo '<p style="margin:0 0 8px 0; font-size:12px; color:#666;">' . esc_html((string) $step['note']) . '</p>';
            }
            if ('' !== trim($cmd)) {
                echo '<div style="position:relative;">';
                echo '<button type="button" class="button button-small gratis-copy-btn" style="position:absolute; top:6px; right:6px;">' . esc_html__('Kopijuoti', 'gratis-security') . '</button>';
                echo '<pre style="background:#f6f7f7; padding:10px 85px 10px 10px; border:1px solid #ccd0d4; border-radius:4px; font-family:monospace; font-size:12px; overflow-x:auto; margin:0;">' . esc_html($cmd) . '</pre>';
                echo '</div>';
            }
            echo '</div>';
        }
        echo '</div>';

        echo '<details style="border:1px solid #dcdcde; border-radius:4px; padding:10px 14px; background:#f9f9f9;">';
        echo '<summary style="cursor:pointer; font-weight:600;">' . esc_html__('WP-CLI komandų sąrašas', 'gratis-security') . '</summary>';
        echo '<pre id="gratis-wizard-wpcli-cmd" style="background:#fff; padding:10px; border:1px solid #ccd0d4; border-radius:4px; font-family:monospace; font-size:12px; overflow-x:auto; margin:10px 0 0 0;">' . esc_html((string) ($recs['wpcli'] ?? '')) . '</pre>';
        echo '</details>';

        echo '</div>'; // End Card 1

        // Card 2: Stored Detections (Plugin Storage)
        $det_counts = (array) ($detections_data['counts'] ?? []);
        $det_rows   = (array) ($detections_data['detections'] ?? []);

        echo '<div class="card" style="max-width: 1150px; padding: 20px; margin-bottom: 20px;">';
        echo '<h2 style="margin:0 0 10px 0;">' . esc_html__('Aptikti incidentai (įskiepio saugykla)', 'gratis-security') . '</h2>';

        echo '<div id="gratis-det-counts" style="display:flex; flex-wrap:wrap; gap:8px; margin-bottom:14px; font-size:12px;">';
        echo '<span style="padding:4px 10px; border-radius:3px; background:#f0f0f1;"><strong>' . esc_html__('Atviri:', 'gratis-security') . '</strong> ' . esc_html((string) ($det_counts['open'] ?? 0)) . '</span>';
        echo '<span style="padding:4px 10px; border-radius:3px; background:#fcf0f1; color:#b32d2e;"><strong>' . esc_html__('Kritiniai:', 'gratis-security') . '</strong> ' . esc_html((string) ($det_counts['critical'] ?? 0)) . '</span>';
        echo '<span style="padding:4px 10px; border-radius:3px; background:#fcf5eb; color:#996800;"><strong>' . esc_html__('Aukšti:', 'gratis-security') . '</strong> ' . esc_html((string) ($det_counts['high'] ?? 0)) . '</span>';
        echo '<span style="padding:4px 10px; border-radius:3px; background:#f0f6fc; color:#135e96;"><strong>' . esc_html__('Vidutiniai:', 'gratis-security') . '</strong> ' . esc_html((string) ($det_counts['medium'] ?? 0)) . '</span>';
        echo '<span style="padding:4px 10px; border-radius:3px; background:#f0f0f1;"><strong>' . esc_html__('Iš viso:', 'gratis-security') . '</strong> ' . esc_html((string) ($det_counts['total'] ?? 0)) . '</span>';
        echo '</div>';

        echo '<div style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:14px;">';
        echo '<input type="search" id="gratis-det-search" placeholder="' . esc_attr__('Ieškoti pagal failą ar taisyklę...', 'gratis-security') . '" style="width:220px; height:32px;">';
        echo '<select id="gratis-det-severity" style="height:32px;">';
        echo '<option value="all">' . esc_html__('Visi sunkumai', 'gratis-security') . '</option>';
        echo '<option value="critical">' . esc_html__('Kritinis', 'gratis-security') . '</option>';
        echo '<option value="high">' . esc_html__('Aukštas', 'gratis-security') . '</option>';
        echo '<option value="medium">' . esc_html__('Vidutinis', 'gratis-security') . '</option>';
        echo '</select>';
        echo '<select id="gratis-det-status" style="height:32px;">';
        echo '<option value="all" selected>' . esc_html__('Visos būsenos', 'gratis-security') . '</option>';
        echo '<option value="open">' . esc_html__('Atviras', 'gratis-security') . '</option>';
        echo '<option value="acknowledged">' . esc_html__('Patvirtintas', 'gratis-security') . '</option>';
        echo '<option value="resolved">' . esc_html__('Išspręstas', 'gratis-security') . '</option>';
        echo '</select>';
        echo '<button type="button" id="gratis-trail-now-btn" class="button button-primary">' . esc_html__('Nuskaityti žurnalus dabar', 'gratis-security') . '</button>';
        echo '<button type="button" id="gratis-det-clear-btn" class="button button-secondary">' . esc_html__('Išvalyti išspręstus', 'gratis-security') . '</button>';
        echo '<span id="gratis-trail-msg" style="font-size:12px; font-weight:600;"></span>';
        echo '</div>';

        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th style="width:145px;">' . esc_html__('Laikas', 'gratis-security') . '</th>';
        echo '<th style="width:85px;">' . esc_html__('Sunkumas', 'gratis-security') . '</th>';
        echo '<th>' . esc_html__('Aptikimas', 'gratis-security') . '</th>';
        echo '<th>' . esc_html__('Failas', 'gratis-security') . '</th>';
        echo '<th style="width:100px;">' . esc_html__('Komponentas', 'gratis-security') . '</th>';
        echo '<th style="width:95px;">' . esc_html__('Būsena', 'gratis-security') . '</th>';
        echo '<th style="width:185px;">' . esc_html__('Veiksmai', 'gratis-security') . '</th>';
        echo '</tr></thead>';
        echo '<tbody id="gratis-detections-body">';
        if (empty($det_rows)) {
            echo '<tr><td colspan="7" style="text-align:center; color:#666; padding:16px;">' . esc_html__('Įrašytų incidentų nėra.', 'gratis-security') . '</td></tr>';
        } else {
            foreach ($det_rows as $det) {
                $det_id   = (string) ($det['id'] ?? '');
                $det_sev  = (string) ($det['severity'] ?? 'medium');
                $det_stat = (string) ($det['status'] ?? 'open');
                $sev_bg   = ('critical' === $det_sev) ? '#d63638' : (('high' === $det_sev) ? '#dba617' : '#2271b1');
                echo '<tr>';
                echo '<td><span style="font-size:12px;">' . esc_html((string) ($det['event_time'] ?? $det['detected_at'] ?? '')) . '</span></td>';
                echo '<td><span style="display:inline-block; padding:2px 7px; border-radius:3px; color:#fff; font-size:11px; font-weight:600; background:' . esc_attr($sev_bg) . ';">' . esc_html(strtoupper($det_sev)) . '</span></td>';
                echo '<td><strong>' . esc_html((string) ($det['title'] ?? '')) . '</strong><div style="font-size:11px; color:#666;">' . esc_html((string) ($det['details'] ?? '')) . '</div></td>';
                echo '<td><code style="word-break:break-all;">' . esc_html((string) ($det['path'] ?? '')) . '</code></td>';
                echo '<td><code>' . esc_html((string) ($det['component'] ?? '')) . '</code></td>';
                echo '<td>' . esc_html($det_stat) . '</td>';
                echo '<td style="white-space:nowrap;">';
                if ('acknowledged' !== $det_stat) {
                    echo '<button type="button" class="button button-small gratis-det-action-btn" data-id="' . esc_attr($det_id) . '" data-status="acknowledged" style="margin-right:4px;">' . esc_html__('Patvirtinti', 'gratis-security') . '</button>';
                }
                if ('resolved' !== $det_stat) {
                    echo '<button type="button" class="button button-small gratis-det-action-btn" data-id="' . esc_attr($det_id) . '" data-status="resolved" style="margin-right:4px;">' . esc_html__('Išspręsta', 'gratis-security') . '</button>';
                }
                if ('open' !== $det_stat) {
                    echo '<button type="button" class="button button-small gratis-det-action-btn" data-id="' . esc_attr($det_id) . '" data-status="open">' . esc_html__('Atidaryti', 'gratis-security') . '</button>';
                }
                echo '</td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table>';
        echo '</div>'; // End Card 2

        // Card 3: Live Log Trail & Filter
        $event_rows   = (array) ($events_data['events'] ?? []);
        $used_sources = (array) ($events_data['sources'] ?? []);
        $state_sources = (array) ($trail_state['sources'] ?? []);

        echo '<div class="card" style="max-width: 1150px; padding: 20px; margin-bottom: 20px;">';
        echo '<h2 style="margin:0 0 8px 0;">' . esc_html__('Realaus laiko žurnalų sekimas ir filtravimas', 'gratis-security') . '</h2>';
        echo '<p id="gratis-log-sources-info" style="font-size:12px; color:#555; margin:0 0 14px 0;">';
        echo esc_html(self::format_log_sources_summary($used_sources, $state_sources));
        echo '</p>';

        echo '<div style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:14px;">';
        echo '<input type="search" id="gratis-log-search" placeholder="' . esc_attr__('Filtruoti žurnalo įrašus...', 'gratis-security') . '" style="width:210px; height:32px;">';
        echo '<select id="gratis-log-event" style="height:32px;">';
        echo '<option value="all">' . esc_html__('Visi įvykiai', 'gratis-security') . '</option>';
        echo '<option value="CLOSE_WRITE">CLOSE_WRITE</option>';
        echo '<option value="CREATE">CREATE</option>';
        echo '<option value="DELETE">DELETE</option>';
        echo '<option value="MOVED_TO">MOVED_TO</option>';
        echo '<option value="AUDIT_WRITE">AUDIT_WRITE</option>';
        echo '</select>';
        echo '<select id="gratis-log-component" style="height:32px;">';
        echo '<option value="all">' . esc_html__('Visi komponentai', 'gratis-security') . '</option>';
        echo '<option value="core">core</option>';
        echo '<option value="mu-plugins">mu-plugins</option>';
        echo '<option value="plugins">plugins</option>';
        echo '<option value="themes">themes</option>';
        echo '<option value="uploads">uploads</option>';
        echo '<option value="config">config</option>';
        echo '<option value="vendor">vendor</option>';
        echo '<option value="other">other</option>';
        echo '</select>';
        echo '<select id="gratis-log-since" style="height:32px;">';
        echo '<option value="15m">' . esc_html__('15 min.', 'gratis-security') . '</option>';
        echo '<option value="1h">' . esc_html__('1 val.', 'gratis-security') . '</option>';
        echo '<option value="24h">' . esc_html__('24 val.', 'gratis-security') . '</option>';
        echo '<option value="7d">' . esc_html__('7 d.', 'gratis-security') . '</option>';
        echo '<option value="all" selected>' . esc_html__('Visas laikas', 'gratis-security') . '</option>';
        echo '</select>';
        echo '<label style="display:inline-flex; align-items:center; gap:4px; font-size:12px;"><input type="checkbox" id="gratis-log-suspicious"> ' . esc_html__('Tik įtartini', 'gratis-security') . '</label>';
        echo '<label style="display:inline-flex; align-items:center; gap:4px; font-size:12px;"><input type="checkbox" id="gratis-log-autotrail"> ' . esc_html__('Auto-atnaujinti (10s)', 'gratis-security') . '</label>';
        echo '<button type="button" id="gratis-log-refresh-btn" class="button button-secondary">' . esc_html__('Filtruoti / Atnaujinti', 'gratis-security') . '</button>';
        echo '</div>';

        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th style="width:155px;">' . esc_html__('Laikas', 'gratis-security') . '</th>';
        echo '<th style="width:75px;">' . esc_html__('Šaltinis', 'gratis-security') . '</th>';
        echo '<th style="width:130px;">' . esc_html__('Įvykis', 'gratis-security') . '</th>';
        echo '<th>' . esc_html__('Failas', 'gratis-security') . '</th>';
        echo '<th style="width:100px;">' . esc_html__('Komponentas', 'gratis-security') . '</th>';
        echo '<th style="width:180px;">' . esc_html__('Įvertinimas', 'gratis-security') . '</th>';
        echo '</tr></thead>';
        echo '<tbody id="gratis-logs-body">';
        if (empty($event_rows)) {
            echo '<tr><td colspan="6" style="text-align:center; color:#666; padding:16px;">' . esc_html__('Žurnalo įrašų nėra arba šaltinis neaktyvus.', 'gratis-security') . '</td></tr>';
        } else {
            foreach ($event_rows as $ev) {
                $preview = isset($ev['detection_preview']) && is_array($ev['detection_preview']) ? $ev['detection_preview'] : null;
                echo '<tr>';
                echo '<td><span style="font-size:12px;">' . esc_html((string) ($ev['time'] ?? '')) . '</span></td>';
                echo '<td><code>' . esc_html((string) ($ev['source'] ?? '')) . '</code></td>';
                echo '<td><code>' . esc_html((string) ($ev['event'] ?? '')) . '</code></td>';
                echo '<td><code style="word-break:break-all;">' . esc_html((string) ($ev['path'] ?? '')) . '</code></td>';
                echo '<td><code>' . esc_html((string) ($ev['component'] ?? '')) . '</code></td>';
                echo '<td>' . ($preview ? esc_html((string) ($preview['severity'] ?? '') . ': ' . (string) ($preview['title'] ?? '')) : '—') . '</td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table>';
        echo '</div>'; // End Card 3

        echo '</div>';

        self::render_server_scripts();
    }

    /**
     * @return array{0:string,1:string}
     */
    private static function wizard_check_badge(string $status): array {
        return match ($status) {
            'ok'           => ['#46b450', '✓ OK'],
            'warn'         => ['#dba617', '⚠ Įspėjimas'],
            'unverifiable' => ['#2271b1', '? Reikia root'],
            default        => ['#d63638', '✗ Trūksta'],
        };
    }

    /**
     * @return array{0:string,1:string}
     */
    private static function wizard_step_badge(string $status): array {
        return match ($status) {
            'done'          => ['#46b450', 'Atlikta'],
            'action_needed' => ['#d63638', 'Reikia atlikti'],
            'manual_verify' => ['#2271b1', 'Patikrinti kaip root'],
            default         => ['#8c8f94', 'Nebūtina'],
        };
    }

    /**
     * @param array<int,string> $used_sources
     * @param array<string,mixed> $state_sources
     */
    private static function format_log_sources_summary(array $used_sources, array $state_sources): string {
        $parts = [];
        if (!empty($used_sources)) {
            $parts[] = 'Aktyvūs šaltiniai: ' . implode(', ', $used_sources);
        } else {
            $parts[] = 'Aktyvių skaitomų žurnalų šaltinių nerasta';
        }
        if (!empty($state_sources)) {
            $cursors = [];
            foreach ($state_sources as $src_path => $cursor) {
                if (!is_array($cursor)) {
                    continue;
                }
                $cursors[] = basename((string) $src_path)
                    . ' (offset: ' . (int) ($cursor['offset'] ?? 0)
                    . ', paskutinį kartą: ' . (string) ($cursor['last_trailed_at'] ?? '-') . ')';
            }
            if (!empty($cursors)) {
                $parts[] = 'Žymekliai: ' . implode('; ', $cursors);
            }
        }
        return implode(' | ', $parts);
    }

    /**
     * Render the General settings tab.
     */
    private static function render_general_tab(): void {
        $settings = self::all();

        echo '<form method="post" action="options.php">';
        settings_fields(self::GROUP);
        echo '<table class="form-table" role="presentation"><tbody>';

        self::checkbox_row($settings, 'waf_enabled', __('Web Application Firewall', 'gratis-security'), __('Blokuoti SQL injekcijas, XSS ir path-traversal užklausas.', 'gratis-security'));
        self::checkbox_row($settings, 'block_xmlrpc', __('Blokuoti XML-RPC', 'gratis-security'), __('Atmesti visas xmlrpc.php užklausas (dažnas brute-force taikinys).', 'gratis-security'));
        self::checkbox_row($settings, 'headers_enabled', __('Saugumo antraštės (Headers)', 'gratis-security'), __('Siųsti X-Frame-Options, X-Content-Type-Options, Referrer-Policy antraštes.', 'gratis-security'));

        echo '<tr><th scope="row"><label for="gs_csp">' . esc_html__('Content-Security-Policy', 'gratis-security') . '</label></th><td>';
        echo '<input type="text" id="gs_csp" class="large-text" name="' . esc_attr(self::OPTION) . '[csp]" value="' . esc_attr((string) $settings['csp']) . '"> ';
        echo '<p class="description">' . esc_html__('Nebūtina. Palikite tuščią, jei nenaudojate CSP.', 'gratis-security') . '</p>';
        echo '</td></tr>';

        self::checkbox_row($settings, 'login_protection', __('Prisijungimo bandymų ribojimas', 'gratis-security'), __('Užrakinti IP po per didelio nesėkmingų prisijungimų skaičiaus.', 'gratis-security'));

        echo '<tr><th scope="row"><label for="gs_max_tries">' . esc_html__('Maksimalus bandymų skaičius', 'gratis-security') . '</label></th><td>';
        echo '<input type="number" min="1" id="gs_max_tries" class="small-text" name="' . esc_attr(self::OPTION) . '[login_max_tries]" value="' . esc_attr((string) (int) $settings['login_max_tries']) . '">';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="gs_lockout">' . esc_html__('Užrakinimo trukmė (minutėmis)', 'gratis-security') . '</label></th><td>';
        echo '<input type="number" min="1" id="gs_lockout" class="small-text" name="' . esc_attr(self::OPTION) . '[login_lockout]" value="' . esc_attr((string) (int) $settings['login_lockout']) . '">';
        echo '</td></tr>';

        self::checkbox_row($settings, 'integrity_enabled', __('Failų stebėjimas įjungtas', 'gratis-security'), __('Tikrinti failų parašus pagal versijuotą manifestą ir WP Core.', 'gratis-security'));
        self::checkbox_row($settings, 'twofa_enabled', __('Dviejų faktorių autentifikacija (2FA)', 'gratis-security'), __('Reikalauti TOTP kodo administratoriams.', 'gratis-security'));

        echo '</tbody></table>';
        submit_button();
        echo '</form>';
    }

    /**
     * Render WAF block log.
     */
    private static function render_block_log(): void {
        echo '<h2>' . esc_html__('Naujausi blokavimai', 'gratis-security') . '</h2>';

        $log = WAF::get_blocks(50);
        if (empty($log)) {
            echo '<p>' . esc_html__('Užblokuotų užklausų nėra.', 'gratis-security') . '</p>';
            return;
        }

        echo '<form method="post" style="margin-bottom:1em;">';
        wp_nonce_field('gratis_security_action');
        echo '<input type="hidden" name="gratis_security_action" value="clear_blocks">';
        submit_button(__('Išvalyti žurnalą', 'gratis-security'), 'secondary', 'submit', false);
        echo '</form>';

        $recent = array_reverse($log);
        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Laikas', 'gratis-security') . '</th><th>' . esc_html__('IP adresas', 'gratis-security') . '</th><th>' . esc_html__('Priežastis', 'gratis-security') . '</th><th>' . esc_html__('URI', 'gratis-security') . '</th></tr></thead><tbody>';
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

        $trail      = EventMonitor::trail();
        $detections = EventMonitor::query_detections(['limit' => 100]);
        $events     = EventMonitor::query_events(['limit' => 100]);

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
            'limit'           => isset($_POST['limit']) ? max(1, min(500, absint($_POST['limit']))) : 100,
        ];

        wp_send_json_success(EventMonitor::query_events($filters));
    }

    /**
     * AJAX handler to list, update status, or clear persisted detections.
     */
    public static function ajax_fim_detections(): void {
        check_ajax_referer('gratis_fim_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $subaction = isset($_POST['subaction']) ? sanitize_key(wp_unslash($_POST['subaction'])) : 'list';
        $filters   = [
            'search'    => isset($_POST['search']) ? sanitize_text_field(wp_unslash($_POST['search'])) : '',
            'severity'  => isset($_POST['severity']) ? sanitize_key(wp_unslash($_POST['severity'])) : '',
            'status'    => isset($_POST['filter_status'])
                ? sanitize_key(wp_unslash($_POST['filter_status']))
                : (('list' === $subaction && isset($_POST['status'])) ? sanitize_key(wp_unslash($_POST['status'])) : ''),
            'component' => isset($_POST['component']) ? sanitize_key(wp_unslash($_POST['component'])) : '',
            'limit'     => isset($_POST['limit']) ? max(1, min(500, absint($_POST['limit']))) : 100,
        ];

        if ('update_status' === $subaction) {
            $id     = isset($_POST['id']) ? sanitize_text_field(wp_unslash($_POST['id'])) : '';
            $status = isset($_POST['status']) ? sanitize_key(wp_unslash($_POST['status'])) : '';
            if ('' === $id || !EventMonitor::update_detection_status($id, $status)) {
                wp_send_json_error(['message' => __('Nepavyko atnaujinti incidento būsenos.', 'gratis-security')]);
            }
            wp_send_json_success(EventMonitor::query_detections($filters));
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

    /**
     * Inline script for Server Diagnostic Wizard, Detections store, and Log Trail UI.
     */
    private static function render_server_scripts(): void {
        $nonce = wp_create_nonce('gratis_fim_nonce');
        $ajax_url = admin_url('admin-ajax.php');
        ?>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var ajaxEndpoint = (typeof ajaxurl !== 'undefined') ? ajaxurl : '<?php echo esc_js($ajax_url); ?>';
            var nonce = '<?php echo esc_js($nonce); ?>';

            function clearNode(node) {
                while (node && node.firstChild) {
                    node.removeChild(node.firstChild);
                }
            }

            function el(tag, text, styles) {
                var node = document.createElement(tag);
                if (typeof text === 'string') {
                    node.textContent = text;
                }
                if (styles) {
                    Object.keys(styles).forEach(function(k) {
                        node.style[k] = styles[k];
                    });
                }
                return node;
            }

            function postAjax(action, params) {
                var fd = new FormData();
                fd.append('action', action);
                fd.append('nonce', nonce);
                Object.keys(params || {}).forEach(function(key) {
                    fd.append(key, params[key]);
                });
                return fetch(ajaxEndpoint, { method: 'POST', body: fd }).then(function(res) { return res.json(); });
            }

            // 1. Server Diagnostic Wizard
            var wizardRunBtn = document.getElementById('gratis-wizard-run-btn');
            var wizardSpinner = document.getElementById('gratis-wizard-spinner');
            var userModeSelect = document.getElementById('gratis-service-user-mode');

            function checkBadgeMeta(status) {
                if (status === 'ok') return ['#46b450', '✓ OK'];
                if (status === 'warn') return ['#dba617', '⚠ Įspėjimas'];
                if (status === 'unverifiable') return ['#2271b1', '? Reikia root'];
                return ['#d63638', '✗ Trūksta'];
            }

            function stepBadgeMeta(status) {
                if (status === 'done') return ['#46b450', 'Atlikta'];
                if (status === 'action_needed') return ['#d63638', 'Reikia atlikti'];
                if (status === 'manual_verify') return ['#2271b1', 'Patikrinti kaip root'];
                return ['#8c8f94', 'Nebūtina'];
            }

            function renderWizard(data) {
                var summary = data.summary || {};
                var os = data.os || {};
                var runtime = data.runtime || {};
                var recs = data.recommendations || {};

                var checkedAt = document.getElementById('gratis-wizard-checked-at');
                if (checkedAt) checkedAt.textContent = data.checked_at || '';

                var badge = document.getElementById('gratis-wizard-overall-badge');
                if (badge) {
                    var ov = summary.overall || 'warn';
                    badge.style.background = ov === 'ok' ? '#46b450' : (ov === 'needs_setup' ? '#d63638' : '#dba617');
                    badge.textContent = ov === 'ok' ? 'Paruošta' : (ov === 'needs_setup' ? 'Reikia sąrankos' : 'Dalinė sąranka');
                }

                var passed = document.getElementById('gratis-wizard-passed-count');
                if (passed) passed.textContent = (summary.passed || 0) + ' / ' + (summary.total || 0);

                var osMeta = document.getElementById('gratis-wizard-os-meta');
                if (osMeta) osMeta.textContent = (os.pretty_name || '') + ' (' + (os.machine || '') + ' / ' + (os.audit_arch || '') + ')';

                var rtMeta = document.getElementById('gratis-wizard-runtime-meta');
                if (rtMeta) rtMeta.textContent = (runtime.user || 'unknown') + ':' + (runtime.group || 'unknown');

                var seMeta = document.getElementById('gratis-wizard-selinux-meta');
                if (seMeta) seMeta.textContent = runtime.selinux || 'unknown';

                var initMeta = document.getElementById('gratis-wizard-init-meta');
                if (initMeta) initMeta.textContent = os.init_system || 'none';

                var tierMeta = document.getElementById('gratis-wizard-tier-meta');
                if (tierMeta) tierMeta.textContent = recs.tier || 'autonomous_php';

                // Checks table
                var checksBody = document.getElementById('gratis-wizard-checks-body');
                if (checksBody) {
                    clearNode(checksBody);
                    (data.checks || []).forEach(function(chk) {
                        var tr = document.createElement('tr');
                        var tdStatus = document.createElement('td');
                        var meta = checkBadgeMeta(chk.status);
                        tdStatus.appendChild(el('span', meta[1], {
                            display: 'inline-block', padding: '2px 8px', borderRadius: '3px',
                            fontSize: '11px', fontWeight: '600', color: '#fff', background: meta[0]
                        }));
                        var tdLabel = document.createElement('td');
                        tdLabel.appendChild(el('strong', chk.label || ''));
                        var tdDetail = document.createElement('td');
                        tdDetail.appendChild(el('code', chk.detail || ''));
                        tr.appendChild(tdStatus);
                        tr.appendChild(tdLabel);
                        tr.appendChild(tdDetail);
                        checksBody.appendChild(tr);
                    });
                }

                // Processes
                var procBox = document.getElementById('gratis-wizard-processes');
                if (procBox) {
                    clearNode(procBox);
                    var procs = data.processes || [];
                    if (!procs.length) {
                        procBox.appendChild(el('span', 'Veikiančių inotifywait procesų neaptikta', { color: '#666' }));
                    } else {
                        procs.forEach(function(proc) {
                            var row = el('div', null, { marginBottom: '4px' });
                            row.appendChild(el('code', 'PID ' + (proc.pid || '')));
                            row.appendChild(document.createTextNode(' (' + (proc.user || '') + ') '));
                            row.appendChild(el('span', proc.matches_web_dir ? 'Kelias sutampa' : 'Kitas kelias', {
                                display: 'inline-block', padding: '1px 6px', borderRadius: '3px',
                                color: '#fff', fontSize: '11px', background: proc.matches_web_dir ? '#46b450' : '#dba617'
                            }));
                            procBox.appendChild(row);
                        });
                    }
                }

                // Tools
                var toolsBox = document.getElementById('gratis-wizard-tools');
                if (toolsBox) {
                    clearNode(toolsBox);
                    var tools = data.tools || {};
                    ['auditctl', 'augenrules', 'inotifywait', 'systemctl', 'wp', 'aide', 'git'].forEach(function(tkey) {
                        var avail = tools[tkey] && tools[tkey].available;
                        toolsBox.appendChild(el('span', tkey + ': ' + (avail ? 'OK' : '—'), {
                            padding: '2px 8px', borderRadius: '3px', color: '#fff',
                            background: avail ? '#46b450' : '#8c8f94'
                        }));
                    });
                    var pkgName = (tools.pkg_manager && tools.pkg_manager.name) ? tools.pkg_manager.name : 'nėra';
                    toolsBox.appendChild(el('span', 'pkg: ' + pkgName, {
                        padding: '2px 8px', borderRadius: '3px', background: '#e5e5e5', color: '#1d2327'
                    }));
                }

                // Steps
                var stepsBox = document.getElementById('gratis-wizard-steps');
                if (stepsBox) {
                    clearNode(stepsBox);
                    (recs.steps || []).forEach(function(step, idx) {
                        var sMeta = stepBadgeMeta(step.status);
                        var card = el('div', null, {
                            border: '1px solid #dcdcde', borderLeft: '4px solid ' + sMeta[0],
                            borderRadius: '4px', padding: '12px 14px', background: '#fff'
                        });
                        var hdr = el('div', null, {
                            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                            gap: '8px', marginBottom: '4px'
                        });
                        hdr.appendChild(el('strong', (idx + 1) + '. ' + (step.title || '')));
                        hdr.appendChild(el('span', sMeta[1], {
                            display: 'inline-block', padding: '2px 8px', borderRadius: '3px',
                            fontSize: '11px', fontWeight: '600', color: '#fff', background: sMeta[0]
                        }));
                        card.appendChild(hdr);

                        if (step.reason) {
                            card.appendChild(el('p', step.reason, { margin: '2px 0 6px 0', fontSize: '13px' }));
                        }
                        if (step.note) {
                            card.appendChild(el('p', step.note, { margin: '0 0 8px 0', fontSize: '12px', color: '#666' }));
                        }
                        var cmd = (step.command || '').trim();
                        if (cmd) {
                            var wrap = el('div', null, { position: 'relative' });
                            var copyBtn = el('button', 'Kopijuoti', { position: 'absolute', top: '6px', right: '6px' });
                            copyBtn.type = 'button';
                            copyBtn.className = 'button button-small gratis-copy-btn';
                            var pre = el('pre', step.command, {
                                background: '#f6f7f7', padding: '10px 85px 10px 10px', border: '1px solid #ccd0d4',
                                borderRadius: '4px', fontFamily: 'monospace', fontSize: '12px', overflowX: 'auto', margin: '0'
                            });
                            wrap.appendChild(copyBtn);
                            wrap.appendChild(pre);
                            card.appendChild(wrap);
                        }
                        stepsBox.appendChild(card);
                    });
                }

                var wpcliPre = document.getElementById('gratis-wizard-wpcli-cmd');
                if (wpcliPre) wpcliPre.textContent = recs.wpcli || '';
            }

            function runWizard() {
                if (wizardRunBtn) wizardRunBtn.disabled = true;
                if (wizardSpinner) wizardSpinner.classList.add('is-active');
                var mode = userModeSelect ? userModeSelect.value : 'php';
                postAjax('gratis_server_wizard', { service_user_mode: mode })
                    .then(function(res) {
                        if (res && res.success && res.data) {
                            renderWizard(res.data);
                        }
                    })
                    .finally(function() {
                        if (wizardRunBtn) wizardRunBtn.disabled = false;
                        if (wizardSpinner) wizardSpinner.classList.remove('is-active');
                    });
            }

            if (wizardRunBtn) wizardRunBtn.addEventListener('click', runWizard);
            if (userModeSelect) userModeSelect.addEventListener('change', runWizard);

            // Copy buttons via event delegation
            document.addEventListener('click', function(e) {
                var btn = e.target.closest ? e.target.closest('.gratis-copy-btn') : null;
                if (!btn) return;
                var parent = btn.parentNode;
                var pre = parent ? parent.querySelector('pre') : null;
                var text = pre ? pre.textContent : '';
                if (!text) return;
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(function() {
                        btn.textContent = 'Nukopijuota ✓';
                        setTimeout(function() { btn.textContent = 'Kopijuoti'; }, 1500);
                    });
                }
            });

            // 2. Detections UI
            var detSearch = document.getElementById('gratis-det-search');
            var detSeverity = document.getElementById('gratis-det-severity');
            var detStatus = document.getElementById('gratis-det-status');
            var detClearBtn = document.getElementById('gratis-det-clear-btn');
            var trailNowBtn = document.getElementById('gratis-trail-now-btn');
            var trailMsg = document.getElementById('gratis-trail-msg');

            function renderDetectionCounts(counts) {
                var box = document.getElementById('gratis-det-counts');
                if (!box || !counts) return;
                clearNode(box);
                var items = [
                    ['Atviri:', counts.open || 0, '#f0f0f1', '#1d2327'],
                    ['Kritiniai:', counts.critical || 0, '#fcf0f1', '#b32d2e'],
                    ['Aukšti:', counts.high || 0, '#fcf5eb', '#996800'],
                    ['Vidutiniai:', counts.medium || 0, '#f0f6fc', '#135e96'],
                    ['Iš viso:', counts.total || 0, '#f0f0f1', '#1d2327']
                ];
                items.forEach(function(item) {
                    var pill = el('span', null, { padding: '4px 10px', borderRadius: '3px', background: item[2], color: item[3] });
                    pill.appendChild(el('strong', item[0] + ' '));
                    pill.appendChild(document.createTextNode(String(item[1])));
                    box.appendChild(pill);
                });
            }

            function renderDetections(data) {
                if (!data) return;
                renderDetectionCounts(data.counts || {});
                var tbody = document.getElementById('gratis-detections-body');
                if (!tbody) return;
                clearNode(tbody);
                var rows = data.detections || [];
                if (!rows.length) {
                    var emptyTr = document.createElement('tr');
                    var emptyTd = el('td', 'Įrašytų incidentų nėra.', { textAlign: 'center', color: '#666', padding: '16px' });
                    emptyTd.colSpan = 7;
                    emptyTr.appendChild(emptyTd);
                    tbody.appendChild(emptyTr);
                    return;
                }
                rows.forEach(function(det) {
                    var tr = document.createElement('tr');
                    var tdTime = document.createElement('td');
                    tdTime.appendChild(el('span', det.event_time || det.detected_at || '', { fontSize: '12px' }));

                    var sev = det.severity || 'medium';
                    var sevBg = sev === 'critical' ? '#d63638' : (sev === 'high' ? '#dba617' : '#2271b1');
                    var tdSev = document.createElement('td');
                    tdSev.appendChild(el('span', sev.toUpperCase(), {
                        display: 'inline-block', padding: '2px 7px', borderRadius: '3px',
                        color: '#fff', fontSize: '11px', fontWeight: '600', background: sevBg
                    }));

                    var tdTitle = document.createElement('td');
                    tdTitle.appendChild(el('strong', det.title || ''));
                    tdTitle.appendChild(el('div', det.details || '', { fontSize: '11px', color: '#666' }));

                    var tdPath = document.createElement('td');
                    tdPath.appendChild(el('code', det.path || '', { wordBreak: 'break-all' }));

                    var tdComp = document.createElement('td');
                    tdComp.appendChild(el('code', det.component || ''));

                    var st = det.status || 'open';
                    var tdStat = el('td', st);

                    var tdAct = el('td', null, { whiteSpace: 'nowrap' });
                    var actions = [];
                    if (st !== 'acknowledged') actions.push(['Patvirtinti', 'acknowledged']);
                    if (st !== 'resolved') actions.push(['Išspręsta', 'resolved']);
                    if (st !== 'open') actions.push(['Atidaryti', 'open']);
                    actions.forEach(function(act, i) {
                        var b = el('button', act[0], i < actions.length - 1 ? { marginRight: '4px' } : null);
                        b.type = 'button';
                        b.className = 'button button-small gratis-det-action-btn';
                        b.setAttribute('data-id', det.id || '');
                        b.setAttribute('data-status', act[1]);
                        tdAct.appendChild(b);
                    });

                    tr.appendChild(tdTime);
                    tr.appendChild(tdSev);
                    tr.appendChild(tdTitle);
                    tr.appendChild(tdPath);
                    tr.appendChild(tdComp);
                    tr.appendChild(tdStat);
                    tr.appendChild(tdAct);
                    tbody.appendChild(tr);
                });
            }

            function currentDetFilters() {
                return {
                    search: detSearch ? detSearch.value.trim() : '',
                    severity: detSeverity ? detSeverity.value : 'all',
                    status: detStatus ? detStatus.value : 'all',
                    limit: '100'
                };
            }

            function fetchDetections() {
                var f = currentDetFilters();
                f.subaction = 'list';
                postAjax('gratis_fim_detections', f).then(function(res) {
                    if (res && res.success) renderDetections(res.data);
                });
            }

            var detTimer = null;
            if (detSearch) {
                detSearch.addEventListener('input', function() {
                    clearTimeout(detTimer);
                    detTimer = setTimeout(fetchDetections, 250);
                });
            }
            if (detSeverity) detSeverity.addEventListener('change', fetchDetections);
            if (detStatus) detStatus.addEventListener('change', fetchDetections);

            var detBody = document.getElementById('gratis-detections-body');
            if (detBody) {
                detBody.addEventListener('click', function(e) {
                    var btn = e.target.closest ? e.target.closest('.gratis-det-action-btn') : null;
                    if (!btn) return;
                    var id = btn.getAttribute('data-id') || '';
                    var newStatus = btn.getAttribute('data-status') || '';
                    if (!id || !newStatus) return;
                    var f = currentDetFilters();
                    postAjax('gratis_fim_detections', {
                        subaction: 'update_status',
                        id: id,
                        status: newStatus,
                        search: f.search,
                        severity: f.severity,
                        filter_status: f.status,
                        limit: f.limit
                    }).then(function(res) {
                        if (res && res.success) renderDetections(res.data);
                    });
                });
            }

            if (detClearBtn) {
                detClearBtn.addEventListener('click', function() {
                    if (!confirm('Išvalyti visus išspręstus incidentus?')) return;
                    var f = currentDetFilters();
                    postAjax('gratis_fim_detections', {
                        subaction: 'clear',
                        clear_status: 'resolved',
                        search: f.search,
                        severity: f.severity,
                        filter_status: f.status,
                        limit: f.limit
                    }).then(function(res) {
                        if (res && res.success) {
                            renderDetections(res.data);
                            if (trailMsg) {
                                trailMsg.style.color = '#46b450';
                                trailMsg.textContent = 'Išvalyta incidentų: ' + (res.data.removed || 0);
                            }
                        }
                    });
                });
            }

            // 3. Log Trail & Filter UI
            var logSearch = document.getElementById('gratis-log-search');
            var logEvent = document.getElementById('gratis-log-event');
            var logComp = document.getElementById('gratis-log-component');
            var logSince = document.getElementById('gratis-log-since');
            var logSusp = document.getElementById('gratis-log-suspicious');
            var logAuto = document.getElementById('gratis-log-autotrail');
            var logRefreshBtn = document.getElementById('gratis-log-refresh-btn');

            function renderSourcesSummary(sources, stateMap) {
                var infoEl = document.getElementById('gratis-log-sources-info');
                if (!infoEl) return;
                var parts = [];
                if (sources && sources.length) {
                    parts.push('Aktyvūs šaltiniai: ' + sources.join(', '));
                } else {
                    parts.push('Aktyvių skaitomų žurnalų šaltinių nerasta');
                }
                if (stateMap && typeof stateMap === 'object') {
                    var cursors = [];
                    Object.keys(stateMap).forEach(function(k) {
                        var c = stateMap[k] || {};
                        var base = k.split('/').pop();
                        cursors.push(base + ' (offset: ' + (c.offset || 0) + ', paskutinį kartą: ' + (c.last_trailed_at || '-') + ')');
                    });
                    if (cursors.length) parts.push('Žymekliai: ' + cursors.join('; '));
                }
                infoEl.textContent = parts.join(' | ');
            }

            function renderLogs(data, stateMap) {
                if (!data) return;
                if (stateMap !== undefined) {
                    renderSourcesSummary(data.sources || [], stateMap);
                }
                var tbody = document.getElementById('gratis-logs-body');
                if (!tbody) return;
                clearNode(tbody);
                var rows = data.events || [];
                if (!rows.length) {
                    var emptyTr = document.createElement('tr');
                    var emptyTd = el('td', 'Žurnalo įrašų nėra arba šaltinis neaktyvus.', { textAlign: 'center', color: '#666', padding: '16px' });
                    emptyTd.colSpan = 6;
                    emptyTr.appendChild(emptyTd);
                    tbody.appendChild(emptyTr);
                    return;
                }
                rows.forEach(function(ev) {
                    var tr = document.createElement('tr');
                    var tdTime = document.createElement('td');
                    tdTime.appendChild(el('span', ev.time || '', { fontSize: '12px' }));
                    var tdSrc = document.createElement('td');
                    tdSrc.appendChild(el('code', ev.source || ''));
                    var tdEv = document.createElement('td');
                    tdEv.appendChild(el('code', ev.event || ''));
                    var tdPath = document.createElement('td');
                    tdPath.appendChild(el('code', ev.path || '', { wordBreak: 'break-all' }));
                    var tdComp = document.createElement('td');
                    tdComp.appendChild(el('code', ev.component || ''));
                    var prev = ev.detection_preview || null;
                    var tdEval = el('td', prev ? ((prev.severity || '') + ': ' + (prev.title || '')) : '—');
                    tr.appendChild(tdTime);
                    tr.appendChild(tdSrc);
                    tr.appendChild(tdEv);
                    tr.appendChild(tdPath);
                    tr.appendChild(tdComp);
                    tr.appendChild(tdEval);
                    tbody.appendChild(tr);
                });
            }

            function fetchLogs() {
                postAjax('gratis_fim_logs', {
                    search: logSearch ? logSearch.value.trim() : '',
                    event: logEvent ? logEvent.value : 'all',
                    component: logComp ? logComp.value : 'all',
                    since: logSince ? logSince.value : 'all',
                    only_suspicious: (logSusp && logSusp.checked) ? '1' : '0',
                    limit: '100'
                }).then(function(res) {
                    if (res && res.success) renderLogs(res.data);
                });
            }

            function runTrailNow(silent) {
                if (trailNowBtn && !silent) trailNowBtn.disabled = true;
                postAjax('gratis_fim_trail', {}).then(function(res) {
                    if (!res || !res.success || !res.data) return;
                    var tr = res.data.trail || {};
                    if (trailMsg) {
                        trailMsg.style.color = '#2271b1';
                        trailMsg.textContent = 'Nuskaityta eilučių: ' + (tr.lines_read || 0) + ', naujų incidentų: ' + (tr.new_detections || 0);
                    }
                    var df = currentDetFilters();
                    if (df.search === '' && df.severity === 'all' && df.status === 'all') {
                        renderDetections(res.data.detections);
                    } else {
                        fetchDetections();
                    }
                    var hasLogFilter = (logSearch && logSearch.value.trim() !== '')
                        || (logEvent && logEvent.value !== 'all')
                        || (logComp && logComp.value !== 'all')
                        || (logSince && logSince.value !== 'all')
                        || (logSusp && logSusp.checked);
                    if (!hasLogFilter) {
                        renderLogs(res.data.events, tr.state || {});
                    } else {
                        renderSourcesSummary((res.data.events && res.data.events.sources) || [], tr.state || {});
                        fetchLogs();
                    }
                }).finally(function() {
                    if (trailNowBtn && !silent) trailNowBtn.disabled = false;
                });
            }

            if (trailNowBtn) trailNowBtn.addEventListener('click', function() { runTrailNow(false); });
            if (logRefreshBtn) logRefreshBtn.addEventListener('click', fetchLogs);

            var logTimer = null;
            if (logSearch) {
                logSearch.addEventListener('input', function() {
                    clearTimeout(logTimer);
                    logTimer = setTimeout(fetchLogs, 250);
                });
            }
            if (logEvent) logEvent.addEventListener('change', fetchLogs);
            if (logComp) logComp.addEventListener('change', fetchLogs);
            if (logSince) logSince.addEventListener('change', fetchLogs);
            if (logSusp) logSusp.addEventListener('change', fetchLogs);

            var autoInterval = null;
            if (logAuto) {
                logAuto.addEventListener('change', function() {
                    if (autoInterval) {
                        clearInterval(autoInterval);
                        autoInterval = null;
                    }
                    if (logAuto.checked) {
                        autoInterval = setInterval(function() { runTrailNow(true); }, 10000);
                    }
                });
            }
            window.addEventListener('beforeunload', function() {
                if (autoInterval) {
                    clearInterval(autoInterval);
                    autoInterval = null;
                }
            });
        });
        </script>
        <?php
    }
}
