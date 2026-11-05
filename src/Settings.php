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
     * Render the Server integration tab for Red Hat / Linux setup.
     */
    private static function render_server_tab(): void {
        $caps = FileIntegrity::detect_server_capabilities();
        $instr = FileIntegrity::get_server_instructions();

        echo '<div class="card" style="max-width: 900px; padding: 20px; margin-top: 10px;">';
        echo '<h2>' . esc_html__('Red Hat Enterprise Linux / Serverio FIM integracija', 'gratis-security') . '</h2>';
        echo '<p>' . esc_html__('Gratis Security sukurtas veikti tiesiogiai su serverio branduolio (kernel) failų stebėjimo posistemėmis. Tai leidžia aptikti failų pakeitimus realiu laiku be jokio PHP ar MySQL našumo praradimo.', 'gratis-security') . '</p>';

        echo '<table class="widefat striped" style="margin-bottom: 25px;">';
        echo '<thead><tr><th>' . esc_html__('Komponentas', 'gratis-security') . '</th><th>' . esc_html__('Būsena serveryje', 'gratis-security') . '</th><th>' . esc_html__('Paskirtis', 'gratis-security') . '</th></tr></thead><tbody>';

        echo '<tr><td><strong>Linux OS</strong></td><td>' . esc_html($caps['os']) . '</td><td>' . esc_html__('Operacinė sistema', 'gratis-security') . '</td></tr>';

        echo '<tr><td><strong>SIMDJSON</strong></td><td>';
        echo $caps['simdjson'] ? '<span style="color:#46b450; font-weight:600;">✓ ' . esc_html__('Aktyvu (v' . $caps['simdjson_version'] . ')', 'gratis-security') . '</span>' : '<span style="color:#999;">' . esc_html__('Neaktyvu (naudojamas native fallback)', 'gratis-security') . '</span>';
        echo '</td><td>' . esc_html__('Aparatinis AVX2/SSE JSON apdorojimas be MySQL', 'gratis-security') . '</td></tr>';

        echo '<tr><td><strong>auditd (Linux Audit)</strong></td><td>';
        echo $caps['auditd_active'] ? '<span style="color:#46b450; font-weight:600;">✓ ' . esc_html__('Veikia (active)', 'gratis-security') . '</span>' : '<span style="color:#2271b1;">' . esc_html__('Įdiegtas / Laukia taisyklių', 'gratis-security') . '</span>';
        echo '</td><td>' . esc_html__('Kernel-level failų stebėjimas su 0% user-space CPU', 'gratis-security') . '</td></tr>';

        echo '<tr><td><strong>inotifywait</strong></td><td>';
        echo $caps['inotifywait'] ? '<span style="color:#46b450; font-weight:600;">✓ ' . esc_html__('Įdiegtas (' . $caps['inotifywait_path'] . ')', 'gratis-security') . '</span>' : '<span style="color:#666;">' . esc_html__('Neįdiegtas', 'gratis-security') . '</span>';
        echo '</td><td>' . esc_html__('Failų sistemos įvykių daemon servisas', 'gratis-security') . '</td></tr>';

        echo '<tr><td><strong>Release Manifests</strong></td><td>';
        echo $caps['has_manifests'] ? '<span style="color:#46b450; font-weight:600;">✓ ' . esc_html__('Aptiktas SOURCE-MANIFEST.sha256', 'gratis-security') . '</span>' : '<span style="color:#666;">' . esc_html__('Nėra manifestų', 'gratis-security') . '</span>';
        echo '</td><td>' . esc_html__('Kriptografiniai deploy leidimo parašai', 'gratis-security') . '</td></tr>';

        echo '</tbody></table>';

        echo '<h3>1. ' . esc_html__('Auditd (Branduolio lygio failų stebėjimas)', 'gratis-security') . '</h3>';
        echo '<p>' . esc_html__('Red Hat Enterprise Linux serveryje įvykdykite šias komandas per SSH su root teisėmis, kad stebėtumėte visus web failų keitimus:', 'gratis-security') . '</p>';
        echo '<pre style="background:#f6f7f7; padding:12px; border:1px solid #ccd0d4; border-radius:4px; font-family:monospace; font-size:12px; overflow-x:auto;">' . esc_html($instr['auditd']) . '</pre>';

        echo '<h3 style="margin-top:25px;">2. ' . esc_html__('Inotifywait Systemd servisas (Realaus laiko įvykių žurnalas)', 'gratis-security') . '</h3>';
        echo '<p>' . esc_html__('Kad serveris realiu laiku registruotų visus failų pakeitimus į JSONL žurnalą, paleiskite šį systemd servisą:', 'gratis-security') . '</p>';
        echo '<pre style="background:#f6f7f7; padding:12px; border:1px solid #ccd0d4; border-radius:4px; font-family:monospace; font-size:12px; overflow-x:auto;">' . esc_html($instr['inotify']) . '</pre>';

        echo '<h3 style="margin-top:25px;">3. ' . esc_html__('WP-CLI periodinė patikra (Cron)', 'gratis-security') . '</h3>';
        echo '<p>' . esc_html__('Galite paleisti patikrą periodiškai per serverio cron:', 'gratis-security') . '</p>';
        echo '<pre style="background:#f6f7f7; padding:12px; border:1px solid #ccd0d4; border-radius:4px; font-family:monospace; font-size:12px; overflow-x:auto;">' . esc_html($instr['wpcli']) . '</pre>';

        echo '</div>';
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
