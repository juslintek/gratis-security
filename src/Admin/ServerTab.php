<?php declare(strict_types=1);

namespace Gratis\Security\Admin;

use Gratis\Security\EventMonitor;
use Gratis\Security\ServerInspector;

defined('ABSPATH') || exit;

/**
 * Server Integration, Paginated Detections Store, and Live Log Trail tab renderer.
 */
final class ServerTab {

    private const PER_PAGE = 20;

    /**
     * Render the Server & Logs tab.
     */
    public static function render(string $nonce): void {
        $inspection      = ServerInspector::inspect('php');
        $detections_data = EventMonitor::query_detections(['page' => 1, 'per_page' => self::PER_PAGE]);
        $events_data     = EventMonitor::query_events(['page' => 1, 'per_page' => self::PER_PAGE]);
        $trail_state     = EventMonitor::get_trail_state();

        $summary   = (array) ($inspection['summary'] ?? []);
        $runtime   = (array) ($inspection['runtime'] ?? []);
        $os        = (array) ($inspection['os'] ?? []);
        $tools     = (array) ($inspection['tools'] ?? []);
        $processes = (array) ($inspection['processes'] ?? []);
        $checks    = (array) ($inspection['checks'] ?? []);
        $recs      = (array) ($inspection['recommendations'] ?? []);
        $steps     = (array) ($recs['steps'] ?? []);

        $overall       = (string) ($summary['overall'] ?? 'warn');
        $overall_label = match ($overall) {
            'ok'          => __('Paruošta', 'gratis-security'),
            'needs_setup' => __('Reikia sąrankos', 'gratis-security'),
            default       => __('Dalinė sąranka', 'gratis-security'),
        };
        $overall_badge = ('ok' === $overall) ? 'gs-badge-ok' : (('needs_setup' === $overall) ? 'gs-badge-danger' : 'gs-badge-warn');

        $runtime_user  = (string) ($runtime['user'] ?? 'unknown');
        $runtime_group = (string) ($runtime['group'] ?? 'unknown');
        $wizard_url    = admin_url('options-general.php?page=gratis-security&tab=wizard');

        // Compact Wizard Banner
        echo '<div class="gs-card">';
        echo '<div style="display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:12px;">';
        echo '<div>';
        echo '<h2 style="margin:0 0 4px 0;">' . esc_html__('Serverio diagnostika ir žurnalai', 'gratis-security') . '</h2>';
        echo '<span style="font-size:12px; color:#646970;">' . esc_html__('Tikrinta:', 'gratis-security') . ' <span id="gratis-wizard-checked-at">' . esc_html((string) ($inspection['checked_at'] ?? '')) . '</span></span>';
        echo '</div>';
        echo '<div class="gs-toolbar" style="margin-bottom:0;">';
        echo '<a href="' . esc_url($wizard_url) . '" class="button button-secondary">' . esc_html__('Atidaryti vedlį', 'gratis-security') . '</a>';
        echo '<button type="button" id="gs-srv-autoconfig-btn" class="button button-secondary">' . esc_html__('Paleisti automatinę PHP konfigūraciją', 'gratis-security') . '</button>';
        echo '<button type="button" id="gratis-wizard-run-btn" class="button button-primary">' . esc_html__('Tikrinti serverį iš naujo', 'gratis-security') . '</button>';
        echo '<span id="gratis-wizard-spinner" class="spinner" style="float:none; margin:0;"></span>';
        echo '</div>';
        echo '</div>';
        echo '<div id="gs-srv-autoconfig-msg" class="gs-msg" style="margin-top:8px;"></div>';

        // Summary bar
        echo '<div class="gs-pills" style="background:#f6f7f7; border:1px solid #dcdcde; border-radius:4px; padding:10px 12px; margin-top:12px;">';
        echo '<span id="gratis-wizard-overall-badge" class="gs-badge ' . esc_attr($overall_badge) . '">' . esc_html($overall_label) . '</span>';
        echo '<span class="gs-pill"><strong>' . esc_html__('Patikros:', 'gratis-security') . '</strong> <span id="gratis-wizard-passed-count">' . esc_html((string) ($summary['passed'] ?? 0) . ' / ' . (string) ($summary['total'] ?? 0)) . '</span></span>';
        echo '<span class="gs-pill"><strong>OS:</strong> <span id="gratis-wizard-os-meta">' . esc_html((string) ($os['pretty_name'] ?? '') . ' (' . (string) ($os['machine'] ?? '') . ' / ' . (string) ($os['audit_arch'] ?? '') . ')') . '</span></span>';
        echo '<span class="gs-pill"><strong>PHP:</strong> <code id="gratis-wizard-runtime-meta">' . esc_html($runtime_user . ':' . $runtime_group) . '</code></span>';
        echo '<span class="gs-pill"><strong>SELinux:</strong> <code id="gratis-wizard-selinux-meta">' . esc_html((string) ($runtime['selinux'] ?? 'unknown')) . '</code></span>';
        echo '<span class="gs-pill"><strong>Init:</strong> <code id="gratis-wizard-init-meta">' . esc_html((string) ($os['init_system'] ?? 'none')) . '</code></span>';
        echo '<span class="gs-pill"><strong>' . esc_html__('Režimas:', 'gratis-security') . '</strong> <code id="gratis-wizard-tier-meta">' . esc_html((string) ($recs['tier'] ?? 'autonomous_php')) . '</code></span>';
        echo '</div>';

        // Live Diagnostic Matrix
        echo '<h3>' . esc_html__('Patikrų suvestinė', 'gratis-security') . '</h3>';
        echo '<table class="widefat striped">';
        echo '<thead><tr><th style="width:140px;">' . esc_html__('Būsena', 'gratis-security') . '</th><th style="width:230px;">' . esc_html__('Patikra', 'gratis-security') . '</th><th>' . esc_html__('Išsami informacija', 'gratis-security') . '</th></tr></thead>';
        echo '<tbody id="gratis-wizard-checks-body">';
        foreach ($checks as $chk) {
            $st = (string) ($chk['status'] ?? 'missing');
            echo '<tr>';
            echo '<td><span class="gs-badge ' . esc_attr(UiHelpers::badge_class($st)) . '">' . esc_html(self::check_status_label($st)) . '</span></td>';
            echo '<td><strong>' . esc_html((string) ($chk['label'] ?? '')) . '</strong></td>';
            echo '<td><code>' . esc_html((string) ($chk['detail'] ?? '')) . '</code></td>';
            echo '</tr>';
        }
        echo '</tbody></table>';

        // Processes & Tools
        echo '<div class="gs-two-col">';
        echo '<div style="background:#f9f9fa; border:1px solid #dcdcde; border-radius:4px; padding:12px;">';
        echo '<div style="font-weight:600; margin-bottom:6px;">' . esc_html__('Veikiantys inotifywait procesai', 'gratis-security') . '</div>';
        echo '<div id="gratis-wizard-processes" style="font-size:12px;">';
        if (empty($processes)) {
            echo '<span style="color:#646970;">' . esc_html__('Veikiančių inotifywait procesų neaptikta', 'gratis-security') . '</span>';
        } else {
            foreach ($processes as $proc) {
                $match_ok = !empty($proc['matches_web_dir']);
                echo '<div style="margin-bottom:4px;">';
                echo '<code>PID ' . esc_html((string) ($proc['pid'] ?? '')) . '</code> (' . esc_html((string) ($proc['user'] ?? '')) . ') ';
                echo '<span class="gs-badge ' . esc_attr($match_ok ? 'gs-badge-ok' : 'gs-badge-warn') . '">';
                echo esc_html($match_ok ? __('Kelias sutampa', 'gratis-security') : __('Kitas kelias', 'gratis-security'));
                echo '</span></div>';
            }
        }
        echo '</div></div>';

        echo '<div style="background:#f9f9fa; border:1px solid #dcdcde; border-radius:4px; padding:12px;">';
        echo '<div style="font-weight:600; margin-bottom:6px;">' . esc_html__('Įrankių prieinamumas', 'gratis-security') . '</div>';
        echo '<div id="gratis-wizard-tools" class="gs-pills">';
        foreach (['auditctl', 'augenrules', 'inotifywait', 'systemctl', 'wp', 'aide', 'git'] as $tkey) {
            $avail = !empty($tools[$tkey]['available']);
            echo '<span class="gs-badge ' . esc_attr($avail ? 'gs-badge-ok' : 'gs-badge-muted') . '">' . esc_html($tkey . ': ' . ($avail ? 'OK' : '—')) . '</span>';
        }
        $has_simd = function_exists('simdjson_decode');
        echo '<span class="gs-badge ' . esc_attr($has_simd ? 'gs-badge-ok' : 'gs-badge-muted') . '">' . esc_html('simdjson: ' . ($has_simd ? 'OK' : 'fallback')) . '</span>';
        $pkg_name = (string) ($tools['pkg_manager']['name'] ?? '');
        echo '<span class="gs-pill">' . esc_html('pkg: ' . ('' !== $pkg_name ? $pkg_name : 'nėra')) . '</span>';
        echo '</div></div>';
        echo '</div>';
        echo '</div>'; // End Diagnostics Card

        // Card 2: Stored Detections (Paginated 20/page)
        $det_counts   = (array) ($detections_data['counts'] ?? []);
        $det_rows     = (array) ($detections_data['detections'] ?? []);
        $det_tot_filt = (int) ($detections_data['total_filtered'] ?? count($det_rows));
        $det_tot_pg   = (int) ($detections_data['total_pages'] ?? 1);

        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('Aptikti incidentai (įskiepio saugykla)', 'gratis-security') . '</h2>';

        echo '<div id="gratis-det-counts" class="gs-pills" style="margin-bottom:12px;">';
        echo '<span class="gs-pill"><strong>' . esc_html__('Atviri:', 'gratis-security') . '</strong> ' . esc_html((string) ($det_counts['open'] ?? 0)) . '</span>';
        echo '<span class="gs-pill" style="background:#fcf0f1; color:#b32d2e;"><strong>' . esc_html__('Kritiniai:', 'gratis-security') . '</strong> ' . esc_html((string) ($det_counts['critical'] ?? 0)) . '</span>';
        echo '<span class="gs-pill" style="background:#fcf5eb; color:#996800;"><strong>' . esc_html__('Aukšti:', 'gratis-security') . '</strong> ' . esc_html((string) ($det_counts['high'] ?? 0)) . '</span>';
        echo '<span class="gs-pill" style="background:#f0f6fc; color:#135e96;"><strong>' . esc_html__('Vidutiniai:', 'gratis-security') . '</strong> ' . esc_html((string) ($det_counts['medium'] ?? 0)) . '</span>';
        echo '<span class="gs-pill"><strong>' . esc_html__('Iš viso:', 'gratis-security') . '</strong> ' . esc_html((string) ($det_counts['total'] ?? 0)) . '</span>';
        echo '</div>';

        echo '<div class="gs-toolbar">';
        echo '<input type="search" id="gratis-det-search" placeholder="' . esc_attr__('Ieškoti pagal failą ar taisyklę...', 'gratis-security') . '" style="width:210px;">';
        echo '<select id="gratis-det-severity">';
        echo '<option value="all">' . esc_html__('Visi sunkumai', 'gratis-security') . '</option>';
        echo '<option value="critical">' . esc_html__('Kritinis', 'gratis-security') . '</option>';
        echo '<option value="high">' . esc_html__('Aukštas', 'gratis-security') . '</option>';
        echo '<option value="medium">' . esc_html__('Vidutinis', 'gratis-security') . '</option>';
        echo '</select>';
        echo '<select id="gratis-det-status">';
        echo '<option value="all" selected>' . esc_html__('Visos būsenos', 'gratis-security') . '</option>';
        echo '<option value="open">' . esc_html__('Atviras', 'gratis-security') . '</option>';
        echo '<option value="acknowledged">' . esc_html__('Patvirtintas', 'gratis-security') . '</option>';
        echo '<option value="resolved">' . esc_html__('Išspręstas', 'gratis-security') . '</option>';
        echo '</select>';
        echo '<button type="button" id="gratis-trail-now-btn" class="button button-primary">' . esc_html__('Nuskaityti žurnalus dabar', 'gratis-security') . '</button>';
        echo '<button type="button" id="gratis-det-purge-btn" class="button button-secondary">' . esc_html__('Išvalyti manifestu patvirtintus', 'gratis-security') . '</button>';
        echo '<button type="button" id="gratis-det-bulk-ack-btn" class="button button-secondary">' . esc_html__('Patvirtinti visus filtruotus', 'gratis-security') . '</button>';
        echo '<button type="button" id="gratis-det-clear-btn" class="button button-secondary">' . esc_html__('Išvalyti išspręstus', 'gratis-security') . '</button>';
        echo '<span id="gratis-trail-msg" class="gs-msg"></span>';
        echo '</div>';

        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th style="width:145px;">' . esc_html__('Laikas', 'gratis-security') . '</th>';
        echo '<th style="width:90px;">' . esc_html__('Sunkumas', 'gratis-security') . '</th>';
        echo '<th>' . esc_html__('Aptikimas', 'gratis-security') . '</th>';
        echo '<th>' . esc_html__('Failas', 'gratis-security') . '</th>';
        echo '<th style="width:100px;">' . esc_html__('Komponentas', 'gratis-security') . '</th>';
        echo '<th style="width:100px;">' . esc_html__('Būsena', 'gratis-security') . '</th>';
        echo '<th style="width:190px;">' . esc_html__('Veiksmai', 'gratis-security') . '</th>';
        echo '</tr></thead>';
        echo '<tbody id="gratis-detections-body">';
        if (empty($det_rows)) {
            echo '<tr><td colspan="7" style="text-align:center; color:#646970; padding:16px;">' . esc_html__('Įrašytų incidentų nėra.', 'gratis-security') . '</td></tr>';
        } else {
            foreach ($det_rows as $det) {
                $det_id   = (string) ($det['id'] ?? '');
                $det_sev  = (string) ($det['severity'] ?? 'medium');
                $det_stat = (string) ($det['status'] ?? 'open');
                echo '<tr>';
                echo '<td><span style="font-size:12px;">' . esc_html((string) ($det['event_time'] ?? $det['detected_at'] ?? '')) . '</span></td>';
                echo '<td><span class="gs-badge ' . esc_attr(UiHelpers::badge_class($det_sev)) . '">' . esc_html(strtoupper($det_sev)) . '</span></td>';
                echo '<td><strong>' . esc_html((string) ($det['title'] ?? '')) . '</strong><div style="font-size:11px; color:#646970;">' . esc_html((string) ($det['details'] ?? '')) . '</div></td>';
                echo '<td><code style="word-break:break-all;">' . esc_html((string) ($det['path'] ?? '')) . '</code></td>';
                echo '<td><code>' . esc_html((string) ($det['component'] ?? '')) . '</code></td>';
                echo '<td><span class="gs-badge ' . esc_attr(UiHelpers::badge_class($det_stat)) . '">' . esc_html($det_stat) . '</span></td>';
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

        echo '<div id="gratis-det-pager" class="gs-pager">';
        echo '<span id="gratis-det-pager-info">' . esc_html(sprintf('Puslapis 1 iš %d (viso %d)', $det_tot_pg, $det_tot_filt)) . '</span>';
        echo '<div class="gs-pager-btns">';
        echo '<button type="button" id="gratis-det-prev" class="button button-small" disabled>' . esc_html__('Ankstesnis', 'gratis-security') . '</button>';
        echo '<button type="button" id="gratis-det-next" class="button button-small"' . ($det_tot_pg <= 1 ? ' disabled' : '') . '>' . esc_html__('Kitas', 'gratis-security') . '</button>';
        echo '</div></div>';
        echo '</div>'; // End Detections Card

        // Card 3: Live Event Log Trail & Filter (Paginated 20/page)
        $event_rows    = (array) ($events_data['events'] ?? []);
        $used_sources  = (array) ($events_data['sources'] ?? []);
        $state_sources = (array) ($trail_state['sources'] ?? []);
        $ev_tot_filt   = (int) ($events_data['total_filtered'] ?? count($event_rows));
        $ev_tot_pg     = (int) ($events_data['total_pages'] ?? 1);

        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('Realaus laiko žurnalų sekimas ir filtravimas', 'gratis-security') . '</h2>';
        echo '<p id="gratis-log-sources-info" style="font-size:12px; color:#50575e; margin:0 0 12px 0;">';
        echo esc_html(self::format_log_sources_summary($used_sources, $state_sources));
        echo '</p>';

        echo '<div class="gs-toolbar">';
        echo '<input type="search" id="gratis-log-search" placeholder="' . esc_attr__('Filtruoti žurnalo įrašus...', 'gratis-security') . '" style="width:200px;">';
        echo '<select id="gratis-log-event">';
        echo '<option value="all">' . esc_html__('Visi įvykiai', 'gratis-security') . '</option>';
        foreach (['CLOSE_WRITE', 'CREATE', 'DELETE', 'MOVED_TO', 'AUDIT_WRITE'] as $ev_name) {
            echo '<option value="' . esc_attr($ev_name) . '">' . esc_html($ev_name) . '</option>';
        }
        echo '</select>';
        echo '<select id="gratis-log-component">';
        echo '<option value="all">' . esc_html__('Visi komponentai', 'gratis-security') . '</option>';
        foreach (['core', 'mu-plugins', 'plugins', 'themes', 'uploads', 'config', 'vendor', 'other'] as $comp_name) {
            echo '<option value="' . esc_attr($comp_name) . '">' . esc_html($comp_name) . '</option>';
        }
        echo '</select>';
        echo '<select id="gratis-log-since">';
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
            echo '<tr><td colspan="6" style="text-align:center; color:#646970; padding:16px;">' . esc_html__('Žurnalo įrašų nėra arba šaltinis neaktyvus.', 'gratis-security') . '</td></tr>';
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

        echo '<div id="gratis-logs-pager" class="gs-pager">';
        echo '<span id="gratis-logs-pager-info">' . esc_html(sprintf('Puslapis 1 iš %d (viso %d)', $ev_tot_pg, $ev_tot_filt)) . '</span>';
        echo '<div class="gs-pager-btns">';
        echo '<button type="button" id="gratis-logs-prev" class="button button-small" disabled>' . esc_html__('Ankstesnis', 'gratis-security') . '</button>';
        echo '<button type="button" id="gratis-logs-next" class="button button-small"' . ($ev_tot_pg <= 1 ? ' disabled' : '') . '>' . esc_html__('Kitas', 'gratis-security') . '</button>';
        echo '</div></div>';
        echo '</div>'; // End Logs Card

        // Optional OS-Level Hardening Commands (clean collapsible details at the bottom)
        echo '<details class="gs-collapsible">';
        echo '<summary>' . esc_html__('Papildomos OS lygio sustiprinimo komandos (auditd / systemd / cron.d / WP-CLI)', 'gratis-security') . '</summary>';
        echo '<p style="margin:10px 0 8px 0; font-size:12px; color:#50575e;">';
        echo esc_html__('Pastaba: Linux branduolio auditd veikia kaip root (PHP negali jo išjungti ar suklastoti žurnalų), tuo tarpu gratis-fim.service (inotifywait) ir wp cron saugiai veikia PHP vartotojo teisėmis.', 'gratis-security');
        echo '</p>';

        echo '<div class="gs-toolbar">';
        echo '<label for="gratis-service-user-mode" style="font-weight:600;">' . esc_html__('Serviso vartotojas:', 'gratis-security') . '</label>';
        echo '<select id="gratis-service-user-mode" style="max-width:100%;">';
        echo '<option value="php" selected>' . esc_html(sprintf('PHP vartotojas (%s:%s) — rekomenduojama', $runtime_user, $runtime_group)) . '</option>';
        echo '<option value="root">' . esc_html__('root — tik skaitymui PHP (/var/log/gratis-fim.jsonl)', 'gratis-security') . '</option>';
        echo '</select>';
        echo '</div>';

        echo '<div id="gratis-wizard-steps">';
        foreach ($steps as $idx => $step) {
            $st  = (string) ($step['status'] ?? 'optional');
            $cmd = trim((string) ($step['command'] ?? ''));
            $ttl = ($idx + 1) . '. ' . (string) ($step['title'] ?? '');
            echo '<div style="margin-top:10px; border:1px solid #dcdcde; border-radius:4px; padding:10px 12px; background:#fff;">';
            echo '<div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">';
            echo '<strong>' . esc_html($ttl) . '</strong>';
            echo '<span class="gs-badge ' . esc_attr(UiHelpers::badge_class($st)) . '">' . esc_html(self::step_status_label($st)) . '</span>';
            echo '</div>';
            if (!empty($step['reason'])) {
                echo '<p style="margin:4px 0; font-size:12px;">' . esc_html((string) $step['reason']) . '</p>';
            }
            if (!empty($step['note'])) {
                echo '<p style="margin:0 0 6px 0; font-size:11px; color:#646970;">' . esc_html((string) $step['note']) . '</p>';
            }
            if ('' !== $cmd) {
                UiHelpers::render_code_block($ttl, $cmd);
            }
            echo '</div>';
        }
        echo '</div>';

        $wpcli_cmd = (string) ($recs['wpcli'] ?? '');
        if ('' !== $wpcli_cmd) {
            echo '<div style="margin-top:12px;">';
            UiHelpers::render_code_block(__('WP-CLI komandų sąrašas', 'gratis-security'), $wpcli_cmd, 'gratis-wizard-wpcli-cmd');
            echo '</div>';
        }
        echo '</details>';

        UiHelpers::render_copy_helper_js();
        self::render_js($nonce);
    }

    private static function check_status_label(string $status): string {
        return match ($status) {
            'ok'           => '✓ OK',
            'warn'         => '⚠ Įspėjimas',
            'unverifiable' => '? Reikia root',
            default        => '✗ Trūksta',
        };
    }

    private static function step_status_label(string $status): string {
        return match ($status) {
            'done'          => 'Atlikta',
            'action_needed' => 'Reikia atlikti',
            'manual_verify' => 'Patikrinti kaip root',
            default         => 'Nebūtina',
        };
    }

    /**
     * @param array<int,string>   $used_sources
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
     * Render safe DOM JS for Server diagnostics, paginated detections, paginated logs, and quick actions.
     */
    private static function render_js(string $nonce): void {
        $ajax_url = admin_url('admin-ajax.php');
        ?>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var ajaxEndpoint = (typeof ajaxurl !== 'undefined') ? ajaxurl : '<?php echo esc_js($ajax_url); ?>';
            var nonce = '<?php echo esc_js($nonce); ?>';
            var perPage = <?php echo (int) self::PER_PAGE; ?>;
            var detPage = 1;
            var logsPage = 1;

            function clearNode(node) {
                while (node && node.firstChild) {
                    node.removeChild(node.firstChild);
                }
            }

            function el(tag, text, cls) {
                var n = document.createElement(tag);
                if (typeof text === 'string') n.textContent = text;
                if (cls) n.className = cls;
                return n;
            }

            function badgeCls(level) {
                var v = String(level || '').toLowerCase();
                if (v === 'ok' || v === 'pass' || v === 'done' || v === 'resolved' || v === 'logged') return 'gs-badge gs-badge-ok';
                if (v === 'warn' || v === 'warning' || v === 'medium' || v === 'acknowledged' || v === 'unverifiable' || v === 'manual_verify') return 'gs-badge gs-badge-warn';
                if (v === 'critical' || v === 'high' || v === 'fail' || v === 'missing' || v === 'action_needed' || v === 'blocked') return 'gs-badge gs-badge-danger';
                if (v === 'info' || v === 'monitor' || v === 'open') return 'gs-badge gs-badge-info';
                return 'gs-badge gs-badge-muted';
            }

            function postAjax(action, params) {
                var fd = new FormData();
                fd.append('action', action);
                fd.append('nonce', nonce);
                Object.keys(params || {}).forEach(function(k) {
                    fd.append(k, params[k]);
                });
                return fetch(ajaxEndpoint, { method: 'POST', body: fd }).then(function(r) { return r.json(); });
            }

            // 1. Server Diagnostic Refresh & Autoconfig
            var wizardRunBtn = document.getElementById('gratis-wizard-run-btn');
            var wizardSpinner = document.getElementById('gratis-wizard-spinner');
            var userModeSelect = document.getElementById('gratis-service-user-mode');
            var autoCfgBtn = document.getElementById('gs-srv-autoconfig-btn');
            var autoCfgMsg = document.getElementById('gs-srv-autoconfig-msg');

            function checkStatusLabel(s) {
                if (s === 'ok') return '✓ OK';
                if (s === 'warn') return '⚠ Įspėjimas';
                if (s === 'unverifiable') return '? Reikia root';
                return '✗ Trūksta';
            }

            function stepStatusLabel(s) {
                if (s === 'done') return 'Atlikta';
                if (s === 'action_needed') return 'Reikia atlikti';
                if (s === 'manual_verify') return 'Patikrinti kaip root';
                return 'Nebūtina';
            }

            function renderCodeBlockDom(parent, title, code) {
                var wrap = el('div', null, 'gs-code-wrap');
                var head = el('div', null, 'gs-code-head');
                head.appendChild(el('span', title));
                var btn = el('button', 'Kopijuoti', 'button button-small gratis-copy-btn');
                btn.type = 'button';
                btn.setAttribute('data-copy', code);
                head.appendChild(btn);
                wrap.appendChild(head);
                wrap.appendChild(el('pre', code, 'gs-code-pre'));
                parent.appendChild(wrap);
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
                    badge.className = badgeCls(ov === 'ok' ? 'ok' : (ov === 'needs_setup' ? 'fail' : 'warn'));
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

                var checksBody = document.getElementById('gratis-wizard-checks-body');
                if (checksBody) {
                    clearNode(checksBody);
                    (data.checks || []).forEach(function(chk) {
                        var tr = document.createElement('tr');
                        var tdSt = document.createElement('td');
                        tdSt.appendChild(el('span', checkStatusLabel(chk.status), badgeCls(chk.status)));
                        var tdLbl = document.createElement('td');
                        tdLbl.appendChild(el('strong', chk.label || ''));
                        var tdDet = document.createElement('td');
                        tdDet.appendChild(el('code', chk.detail || ''));
                        tr.appendChild(tdSt);
                        tr.appendChild(tdLbl);
                        tr.appendChild(tdDet);
                        checksBody.appendChild(tr);
                    });
                }

                var procBox = document.getElementById('gratis-wizard-processes');
                if (procBox) {
                    clearNode(procBox);
                    var procs = data.processes || [];
                    if (!procs.length) {
                        var sp = el('span', 'Veikiančių inotifywait procesų neaptikta');
                        sp.style.color = '#646970';
                        procBox.appendChild(sp);
                    } else {
                        procs.forEach(function(proc) {
                            var row = document.createElement('div');
                            row.style.marginBottom = '4px';
                            row.appendChild(el('code', 'PID ' + (proc.pid || '')));
                            row.appendChild(document.createTextNode(' (' + (proc.user || '') + ') '));
                            row.appendChild(el('span', proc.matches_web_dir ? 'Kelias sutampa' : 'Kitas kelias', badgeCls(proc.matches_web_dir ? 'ok' : 'warn')));
                            procBox.appendChild(row);
                        });
                    }
                }

                var toolsBox = document.getElementById('gratis-wizard-tools');
                if (toolsBox) {
                    clearNode(toolsBox);
                    var tools = data.tools || {};
                    ['auditctl', 'augenrules', 'inotifywait', 'systemctl', 'wp', 'aide', 'git'].forEach(function(tkey) {
                        var avail = tools[tkey] && tools[tkey].available;
                        toolsBox.appendChild(el('span', tkey + ': ' + (avail ? 'OK' : '—'), badgeCls(avail ? 'ok' : 'muted')));
                    });
                    var pkgName = (tools.pkg_manager && tools.pkg_manager.name) ? tools.pkg_manager.name : 'nėra';
                    toolsBox.appendChild(el('span', 'pkg: ' + pkgName, 'gs-pill'));
                }

                var stepsBox = document.getElementById('gratis-wizard-steps');
                if (stepsBox) {
                    clearNode(stepsBox);
                    (recs.steps || []).forEach(function(step, idx) {
                        var st = step.status || 'optional';
                        var ttl = (idx + 1) + '. ' + (step.title || '');
                        var card = document.createElement('div');
                        card.style.marginTop = '10px';
                        card.style.border = '1px solid #dcdcde';
                        card.style.borderRadius = '4px';
                        card.style.padding = '10px 12px';
                        card.style.background = '#fff';

                        var hdr = document.createElement('div');
                        hdr.style.display = 'flex';
                        hdr.style.justifyContent = 'space-between';
                        hdr.style.alignItems = 'center';
                        hdr.appendChild(el('strong', ttl));
                        hdr.appendChild(el('span', stepStatusLabel(st), badgeCls(st)));
                        card.appendChild(hdr);

                        if (step.reason) {
                            var pR = el('p', step.reason);
                            pR.style.margin = '4px 0';
                            pR.style.fontSize = '12px';
                            card.appendChild(pR);
                        }
                        if (step.note) {
                            var pN = el('p', step.note);
                            pN.style.margin = '0 0 6px 0';
                            pN.style.fontSize = '11px';
                            pN.style.color = '#646970';
                            card.appendChild(pN);
                        }
                        var cmd = (step.command || '').trim();
                        if (cmd) renderCodeBlockDom(card, ttl, cmd);
                        stepsBox.appendChild(card);
                    });
                }

                var wpcliPre = document.getElementById('gratis-wizard-wpcli-cmd');
                if (wpcliPre) {
                    wpcliPre.textContent = recs.wpcli || '';
                    var wrap = wpcliPre.closest('.gs-code-wrap');
                    var cp = wrap ? wrap.querySelector('.gratis-copy-btn') : null;
                    if (cp) cp.setAttribute('data-copy', recs.wpcli || '');
                }
            }

            function runWizard() {
                if (wizardRunBtn) wizardRunBtn.disabled = true;
                if (wizardSpinner) wizardSpinner.classList.add('is-active');
                var mode = userModeSelect ? userModeSelect.value : 'php';
                postAjax('gratis_server_wizard', { service_user_mode: mode })
                    .then(function(res) {
                        if (res && res.success && res.data) renderWizard(res.data);
                    })
                    .finally(function() {
                        if (wizardRunBtn) wizardRunBtn.disabled = false;
                        if (wizardSpinner) wizardSpinner.classList.remove('is-active');
                    });
            }

            if (wizardRunBtn) wizardRunBtn.addEventListener('click', runWizard);
            if (userModeSelect) userModeSelect.addEventListener('change', runWizard);

            if (autoCfgBtn) {
                autoCfgBtn.addEventListener('click', function() {
                    autoCfgBtn.disabled = true;
                    if (wizardSpinner) wizardSpinner.classList.add('is-active');
                    if (autoCfgMsg) {
                        autoCfgMsg.style.color = '#2271b1';
                        autoCfgMsg.textContent = 'Vykdoma PHP konfigūracija...';
                    }
                    postAjax('gratis_wizard_autoconfig', {
                        waf_mode: 'monitor',
                        sync_wp_checksums: '1',
                        run_scans: '1'
                    }).then(function(res) {
                        if (res && res.success && res.data) {
                            if (autoCfgMsg) {
                                autoCfgMsg.style.color = '#00a32a';
                                autoCfgMsg.textContent = 'PHP konfigūracija atlikta! Įvertis: ' + ((res.data.audit && res.data.audit.score) || 0) + '/100.';
                            }
                            runWizard();
                            fetchDetections(1);
                        } else if (autoCfgMsg) {
                            autoCfgMsg.style.color = '#d63638';
                            autoCfgMsg.textContent = 'Konfigūracija nepavyko.';
                        }
                    }).finally(function() {
                        autoCfgBtn.disabled = false;
                        if (wizardSpinner) wizardSpinner.classList.remove('is-active');
                    });
                });
            }

            // 2. Paginated Detections UI
            var detSearch = document.getElementById('gratis-det-search');
            var detSeverity = document.getElementById('gratis-det-severity');
            var detStatus = document.getElementById('gratis-det-status');
            var detClearBtn = document.getElementById('gratis-det-clear-btn');
            var detPurgeBtn = document.getElementById('gratis-det-purge-btn');
            var detBulkAckBtn = document.getElementById('gratis-det-bulk-ack-btn');
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
                    var pill = el('span', null, 'gs-pill');
                    pill.style.background = item[2];
                    pill.style.color = item[3];
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
                    var emptyTd = el('td', 'Įrašytų incidentų nėra.');
                    emptyTd.colSpan = 7;
                    emptyTd.style.textAlign = 'center';
                    emptyTd.style.color = '#646970';
                    emptyTd.style.padding = '16px';
                    emptyTr.appendChild(emptyTd);
                    tbody.appendChild(emptyTr);
                } else {
                    rows.forEach(function(det) {
                        var tr = document.createElement('tr');
                        var tdTime = document.createElement('td');
                        var spT = el('span', det.event_time || det.detected_at || '');
                        spT.style.fontSize = '12px';
                        tdTime.appendChild(spT);

                        var sev = det.severity || 'medium';
                        var tdSev = document.createElement('td');
                        tdSev.appendChild(el('span', sev.toUpperCase(), badgeCls(sev)));

                        var tdTitle = document.createElement('td');
                        tdTitle.appendChild(el('strong', det.title || ''));
                        var dDiv = el('div', det.details || '');
                        dDiv.style.fontSize = '11px';
                        dDiv.style.color = '#646970';
                        tdTitle.appendChild(dDiv);

                        var tdPath = document.createElement('td');
                        var cPath = el('code', det.path || '');
                        cPath.style.wordBreak = 'break-all';
                        tdPath.appendChild(cPath);

                        var tdComp = document.createElement('td');
                        tdComp.appendChild(el('code', det.component || ''));

                        var st = det.status || 'open';
                        var tdStat = document.createElement('td');
                        tdStat.appendChild(el('span', st, badgeCls(st)));

                        var tdAct = document.createElement('td');
                        tdAct.style.whiteSpace = 'nowrap';
                        var actions = [];
                        if (st !== 'acknowledged') actions.push(['Patvirtinti', 'acknowledged']);
                        if (st !== 'resolved') actions.push(['Išspręsta', 'resolved']);
                        if (st !== 'open') actions.push(['Atidaryti', 'open']);
                        actions.forEach(function(act, i) {
                            var b = el('button', act[0], 'button button-small gratis-det-action-btn');
                            b.type = 'button';
                            if (i < actions.length - 1) b.style.marginRight = '4px';
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

                detPage = Number(data.page || 1);
                var totPages = Number(data.total_pages || 1);
                var totFilt = Number(data.total_filtered !== undefined ? data.total_filtered : rows.length);
                var infoEl = document.getElementById('gratis-det-pager-info');
                var prevBtn = document.getElementById('gratis-det-prev');
                var nextBtn = document.getElementById('gratis-det-next');
                if (infoEl) infoEl.textContent = 'Puslapis ' + detPage + ' iš ' + totPages + ' (viso ' + totFilt + ')';
                if (prevBtn) prevBtn.disabled = detPage <= 1;
                if (nextBtn) nextBtn.disabled = detPage >= totPages;
            }

            function currentDetFilters(pageOverride) {
                return {
                    search: detSearch ? detSearch.value.trim() : '',
                    severity: detSeverity ? detSeverity.value : 'all',
                    status: detStatus ? detStatus.value : 'all',
                    page: String(pageOverride || detPage),
                    per_page: String(perPage)
                };
            }

            function fetchDetections(pageOverride) {
                var f = currentDetFilters(pageOverride);
                f.subaction = 'list';
                postAjax('gratis_fim_detections', f).then(function(res) {
                    if (res && res.success) renderDetections(res.data);
                });
            }

            var detTimer = null;
            if (detSearch) {
                detSearch.addEventListener('input', function() {
                    clearTimeout(detTimer);
                    detTimer = setTimeout(function() { fetchDetections(1); }, 250);
                });
            }
            if (detSeverity) detSeverity.addEventListener('change', function() { fetchDetections(1); });
            if (detStatus) detStatus.addEventListener('change', function() { fetchDetections(1); });

            var detPrev = document.getElementById('gratis-det-prev');
            var detNext = document.getElementById('gratis-det-next');
            if (detPrev) detPrev.addEventListener('click', function() { if (detPage > 1) fetchDetections(detPage - 1); });
            if (detNext) detNext.addEventListener('click', function() { fetchDetections(detPage + 1); });

            var detBody = document.getElementById('gratis-detections-body');
            if (detBody) {
                detBody.addEventListener('click', function(e) {
                    var btn = e.target && e.target.closest ? e.target.closest('.gratis-det-action-btn') : null;
                    if (!btn) return;
                    var id = btn.getAttribute('data-id') || '';
                    var newStatus = btn.getAttribute('data-status') || '';
                    if (!id || !newStatus) return;
                    var f = currentDetFilters(detPage);
                    postAjax('gratis_fim_detections', {
                        subaction: 'update_status',
                        id: id,
                        status: newStatus,
                        search: f.search,
                        severity: f.severity,
                        filter_status: f.status,
                        page: f.page,
                        per_page: f.per_page
                    }).then(function(res) {
                        if (res && res.success) renderDetections(res.data);
                    });
                });
            }

            if (detPurgeBtn) {
                detPurgeBtn.addEventListener('click', function() {
                    var f = currentDetFilters(1);
                    postAjax('gratis_fim_detections', {
                        subaction: 'purge_verified',
                        search: f.search,
                        severity: f.severity,
                        filter_status: f.status,
                        page: '1',
                        per_page: f.per_page
                    }).then(function(res) {
                        if (res && res.success) {
                            renderDetections(res.data);
                            if (trailMsg) {
                                trailMsg.style.color = '#00a32a';
                                trailMsg.textContent = 'Išvalyta manifestu patvirtintų įrašų: ' + (res.data.removed || 0);
                            }
                        }
                    });
                });
            }

            if (detBulkAckBtn) {
                detBulkAckBtn.addEventListener('click', function() {
                    if (!confirm('Patvirtinti visus filtruotus incidentus?')) return;
                    var f = currentDetFilters(1);
                    postAjax('gratis_fim_detections', {
                        subaction: 'bulk_status',
                        new_status: 'acknowledged',
                        search: f.search,
                        severity: f.severity,
                        filter_status: f.status,
                        page: '1',
                        per_page: f.per_page
                    }).then(function(res) {
                        if (res && res.success) {
                            renderDetections(res.data);
                            if (trailMsg) {
                                trailMsg.style.color = '#00a32a';
                                trailMsg.textContent = 'Patvirtinta incidentų: ' + (res.data.updated || 0);
                            }
                        }
                    });
                });
            }

            if (detClearBtn) {
                detClearBtn.addEventListener('click', function() {
                    if (!confirm('Išvalyti visus išspręstus incidentus?')) return;
                    var f = currentDetFilters(1);
                    postAjax('gratis_fim_detections', {
                        subaction: 'clear',
                        clear_status: 'resolved',
                        search: f.search,
                        severity: f.severity,
                        filter_status: f.status,
                        page: '1',
                        per_page: f.per_page
                    }).then(function(res) {
                        if (res && res.success) {
                            renderDetections(res.data);
                            if (trailMsg) {
                                trailMsg.style.color = '#00a32a';
                                trailMsg.textContent = 'Išvalyta incidentų: ' + (res.data.removed || 0);
                            }
                        }
                    });
                });
            }

            // 3. Paginated Log Trail & Filter UI
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
                if (stateMap !== undefined) renderSourcesSummary(data.sources || [], stateMap);
                var tbody = document.getElementById('gratis-logs-body');
                if (!tbody) return;
                clearNode(tbody);
                var rows = data.events || [];
                if (!rows.length) {
                    var emptyTr = document.createElement('tr');
                    var emptyTd = el('td', 'Žurnalo įrašų nėra arba šaltinis neaktyvus.');
                    emptyTd.colSpan = 6;
                    emptyTd.style.textAlign = 'center';
                    emptyTd.style.color = '#646970';
                    emptyTd.style.padding = '16px';
                    emptyTr.appendChild(emptyTd);
                    tbody.appendChild(emptyTr);
                } else {
                    rows.forEach(function(ev) {
                        var tr = document.createElement('tr');
                        var tdTime = document.createElement('td');
                        var sp = el('span', ev.time || '');
                        sp.style.fontSize = '12px';
                        tdTime.appendChild(sp);
                        var tdSrc = document.createElement('td');
                        tdSrc.appendChild(el('code', ev.source || ''));
                        var tdEv = document.createElement('td');
                        tdEv.appendChild(el('code', ev.event || ''));
                        var tdPath = document.createElement('td');
                        var cp = el('code', ev.path || '');
                        cp.style.wordBreak = 'break-all';
                        tdPath.appendChild(cp);
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

                logsPage = Number(data.page || 1);
                var totPages = Number(data.total_pages || 1);
                var totFilt = Number(data.total_filtered !== undefined ? data.total_filtered : rows.length);
                var infoEl = document.getElementById('gratis-logs-pager-info');
                var prevBtn = document.getElementById('gratis-logs-prev');
                var nextBtn = document.getElementById('gratis-logs-next');
                if (infoEl) infoEl.textContent = 'Puslapis ' + logsPage + ' iš ' + totPages + ' (viso ' + totFilt + ')';
                if (prevBtn) prevBtn.disabled = logsPage <= 1;
                if (nextBtn) nextBtn.disabled = logsPage >= totPages;
            }

            function fetchLogs(pageOverride) {
                postAjax('gratis_fim_logs', {
                    search: logSearch ? logSearch.value.trim() : '',
                    event: logEvent ? logEvent.value : 'all',
                    component: logComp ? logComp.value : 'all',
                    since: logSince ? logSince.value : 'all',
                    only_suspicious: (logSusp && logSusp.checked) ? '1' : '0',
                    page: String(pageOverride || logsPage),
                    per_page: String(perPage)
                }).then(function(res) {
                    if (res && res.success) renderLogs(res.data);
                });
            }

            function runTrailNow(silent) {
                if (trailNowBtn && !silent) trailNowBtn.disabled = true;
                postAjax('gratis_fim_trail', { per_page: String(perPage) }).then(function(res) {
                    if (!res || !res.success || !res.data) return;
                    var tr = res.data.trail || {};
                    if (trailMsg) {
                        trailMsg.style.color = '#2271b1';
                        trailMsg.textContent = 'Nuskaityta eilučių: ' + (tr.lines_read || 0) + ', naujų incidentų: ' + (tr.new_detections || 0);
                    }
                    fetchDetections(1);
                    renderSourcesSummary((res.data.events && res.data.events.sources) || [], tr.state || {});
                    fetchLogs(1);
                }).finally(function() {
                    if (trailNowBtn && !silent) trailNowBtn.disabled = false;
                });
            }

            if (trailNowBtn) trailNowBtn.addEventListener('click', function() { runTrailNow(false); });
            if (logRefreshBtn) logRefreshBtn.addEventListener('click', function() { fetchLogs(logsPage); });

            var logsPrev = document.getElementById('gratis-logs-prev');
            var logsNext = document.getElementById('gratis-logs-next');
            if (logsPrev) logsPrev.addEventListener('click', function() { if (logsPage > 1) fetchLogs(logsPage - 1); });
            if (logsNext) logsNext.addEventListener('click', function() { fetchLogs(logsPage + 1); });

            var logTimer = null;
            if (logSearch) {
                logSearch.addEventListener('input', function() {
                    clearTimeout(logTimer);
                    logTimer = setTimeout(function() { fetchLogs(1); }, 250);
                });
            }
            if (logEvent) logEvent.addEventListener('change', function() { fetchLogs(1); });
            if (logComp) logComp.addEventListener('change', function() { fetchLogs(1); });
            if (logSince) logSince.addEventListener('change', function() { fetchLogs(1); });
            if (logSusp) logSusp.addEventListener('change', function() { fetchLogs(1); });

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
