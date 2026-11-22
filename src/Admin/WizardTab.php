<?php declare(strict_types=1);

namespace Gratis\Security\Admin;

use Gratis\Security\EventMonitor;
use Gratis\Security\FileIntegrity;
use Gratis\Security\MalwareScanner;
use Gratis\Security\RequestGuard;
use Gratis\Security\Settings;
use Gratis\Security\SetupWizard;
use Gratis\Security\SignatureFeed;

defined('ABSPATH') || exit;

/**
 * Interactive PHP-first Setup Wizard & Security Overview tab renderer.
 */
final class WizardTab {

    /**
     * Render the Wizard & Overview tab.
     */
    public static function render(string $nonce): void {
        $diag                = SetupWizard::diagnose('php');
        $audit               = (array) ($diag['audit'] ?? []);
        $php_caps            = (array) ($diag['php_capabilities'] ?? []);
        $signatures          = (array) ($diag['signatures'] ?? []);
        $malware             = is_array($diag['malware'] ?? null) ? $diag['malware'] : null;
        $server              = (array) ($diag['server'] ?? []);
        $det_counts          = (array) ($diag['detections_counts'] ?? []);
        $req_counts          = (array) ($diag['requests_counts'] ?? []);
        $wizard_completed_at = (string) ($diag['wizard_completed_at'] ?? '');

        $score       = (int) ($audit['score'] ?? 0);
        $grade       = (string) ($audit['grade'] ?? 'F');
        $audit_cnt   = (array) ($audit['counts'] ?? []);
        $audit_checks = (array) ($audit['checks'] ?? []);

        $runtime      = (array) ($server['runtime'] ?? []);
        $os           = (array) ($server['os'] ?? []);
        $recs         = (array) ($server['recommendations'] ?? []);
        $runtime_user = (string) ($runtime['user'] ?? 'unknown');
        $runtime_grp  = (string) ($runtime['group'] ?? 'unknown');
        $os_name      = (string) ($os['pretty_name'] ?? PHP_OS_FAMILY);

        $settings     = Settings::all();
        $waf_mode     = RequestGuard::get_mode();
        $fim_on       = !empty($settings['integrity_enabled']);
        $mal_cron_on  = !empty($settings['malware_auto_scan']);
        $sig_cron_on  = !empty($settings['signature_auto_update']);
        $twofa_on     = !empty($settings['twofa_enabled']);

        $score_bg = ($score >= 80) ? '#00a32a' : (($score >= 60) ? '#dba617' : '#d63638');

        // Hero Card
        echo '<div class="gs-card">';
        echo '<div class="gs-score-hero">';
        echo '<div class="gs-score-main">';
        echo '<div id="gs-wiz-score-circle" class="gs-score-circle" style="background:' . esc_attr($score_bg) . ';">';
        echo '<span id="gs-wiz-score-val" class="gs-score-num">' . esc_html((string) $score) . '</span>';
        echo '<span id="gs-wiz-score-grade" class="gs-score-grade">' . esc_html(sprintf('Įvertis %s / 100', $grade)) . '</span>';
        echo '</div>';
        echo '<div>';
        echo '<h2 style="margin:0 0 4px 0;">' . esc_html__('Saugumo būklė ir PHP sąrankos vedlys', 'gratis-security') . '</h2>';
        echo '<p style="margin:0 0 8px 0; color:#50575e; font-size:13px;">';
        echo esc_html(sprintf(
            'Patikrinta: %d iš %d atitinka | PHP: %s:%s | OS: %s',
            (int) ($audit_cnt['pass'] ?? 0),
            (int) ($audit_cnt['total'] ?? 0),
            $runtime_user,
            $runtime_grp,
            $os_name
        ));
        echo '</p>';
        echo '<div id="gs-wiz-hero-pills" class="gs-pills">';
        echo '<span class="gs-pill"><strong>FIM:</strong> <span class="gs-badge ' . esc_attr($fim_on ? 'gs-badge-ok' : 'gs-badge-warn') . '">' . esc_html($fim_on ? 'Įjungta' : 'Išjungta') . '</span></span>';
        echo '<span class="gs-pill"><strong>Malware:</strong> <span class="gs-badge ' . esc_attr($malware ? 'gs-badge-ok' : 'gs-badge-warn') . '">' . esc_html($malware ? 'Nuskaityta' : 'Nenuskaityta') . '</span></span>';
        echo '<span class="gs-pill"><strong>Užklausos:</strong> <span class="gs-badge ' . esc_attr('block' === $waf_mode ? 'gs-badge-ok' : ('monitor' === $waf_mode ? 'gs-badge-info' : 'gs-badge-warn')) . '">' . esc_html(strtoupper($waf_mode)) . '</span></span>';
        echo '<span class="gs-pill"><strong>Parašai:</strong> <span class="gs-badge ' . esc_attr(!empty($signatures['last_updated']) ? 'gs-badge-ok' : 'gs-badge-warn') . '">' . esc_html((string) ($signatures['version'] ?? SignatureFeed::BUILTIN_VERSION)) . '</span></span>';
        echo '<span class="gs-pill"><strong>2FA:</strong> <span class="gs-badge ' . esc_attr($twofa_on ? 'gs-badge-ok' : 'gs-badge-muted') . '">' . esc_html($twofa_on ? 'Privaloma' : 'Neprivaloma') . '</span></span>';
        echo '</div>';
        echo '</div>';
        echo '</div>';

        echo '<div style="text-align:right;">';
        echo '<div style="font-size:12px; color:#646970; margin-bottom:4px;">' . esc_html__('Vedlio būsena', 'gratis-security') . '</div>';
        if ('' !== $wizard_completed_at) {
            echo '<span id="gs-wiz-completed-badge" class="gs-badge gs-badge-ok">' . esc_html__('Sukonfigūruota', 'gratis-security') . '</span>';
            echo '<div id="gs-wiz-completed-at" style="font-size:11px; color:#646970; margin-top:4px;">' . esc_html($wizard_completed_at) . '</div>';
        } else {
            echo '<span id="gs-wiz-completed-badge" class="gs-badge gs-badge-warn">' . esc_html__('Dar nebaigta', 'gratis-security') . '</span>';
            echo '<div id="gs-wiz-completed-at" style="font-size:11px; color:#646970; margin-top:4px;">' . esc_html__('Spauskite mygtuką žemiau', 'gratis-security') . '</div>';
        }
        echo '</div>';
        echo '</div>';
        echo '</div>';

        // Step 1: Environment & PHP capabilities + Security Audit checklist
        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('1 žingsnis. Aplinkos ir PHP galimybių patikra', 'gratis-security') . '</h2>';

        $exts   = (array) ($php_caps['extensions'] ?? []);
        $clamav = (array) ($php_caps['clamav'] ?? []);
        $stor_w = !empty($php_caps['storage_writable']);

        echo '<div class="gs-pills" style="margin-bottom:12px;">';
        foreach (['simdjson', 'inotify', 'openssl', 'curl', 'posix', 'fileinfo'] as $ext) {
            $ok = !empty($exts[$ext]);
            echo '<span class="gs-pill">' . esc_html($ext) . ': <span class="gs-badge ' . esc_attr($ok ? 'gs-badge-ok' : 'gs-badge-muted') . '">' . esc_html($ok ? 'OK' : '—') . '</span></span>';
        }
        echo '<span class="gs-pill">clamav: <span class="gs-badge ' . esc_attr(!empty($clamav['available']) ? 'gs-badge-ok' : 'gs-badge-muted') . '">' . esc_html(!empty($clamav['available']) ? (string) ($clamav['type'] ?? 'OK') : '—') . '</span></span>';
        echo '<span class="gs-pill">storage_writable: <span class="gs-badge ' . esc_attr($stor_w ? 'gs-badge-ok' : 'gs-badge-danger') . '">' . esc_html($stor_w ? 'Taip' : 'Ne') . '</span></span>';
        echo '</div>';

        if (!empty($php_caps['disable_wp_cron'])) {
            echo '<div style="padding:8px 12px; background:#fcf5eb; border-left:4px solid #dba617; font-size:12px; margin-bottom:12px;">';
            echo esc_html__('Pastaba: DISABLE_WP_CRON yra true — įsitikinkite, kad sistemos cron reguliariai vykdo `wp cron event run --due-now`.', 'gratis-security');
            echo '</div>';
        } else {
            echo '<p style="margin:0 0 12px 0; font-size:12px; color:#646970;">' . esc_html((string) ($php_caps['wp_cron_note'] ?? '')) . '</p>';
        }

        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th style="width:110px;">' . esc_html__('Būsena', 'gratis-security') . '</th>';
        echo '<th style="width:230px;">' . esc_html__('Patikra', 'gratis-security') . '</th>';
        echo '<th style="width:70px;">' . esc_html__('Svoris', 'gratis-security') . '</th>';
        echo '<th>' . esc_html__('Išsami informacija', 'gratis-security') . '</th>';
        echo '<th>' . esc_html__('Rekomendacija', 'gratis-security') . '</th>';
        echo '</tr></thead>';
        echo '<tbody id="gs-wiz-audit-body">';
        foreach ($audit_checks as $chk) {
            $st  = (string) ($chk['status'] ?? 'fail');
            $lbl = match ($st) {
                'pass' => 'Atitinka',
                'warn' => 'Įspėjimas',
                default => 'Trūksta',
            };
            echo '<tr>';
            echo '<td><span class="gs-badge ' . esc_attr(UiHelpers::badge_class($st)) . '">' . esc_html($lbl) . '</span></td>';
            echo '<td><strong>' . esc_html((string) ($chk['label'] ?? '')) . '</strong></td>';
            echo '<td>' . esc_html((string) (int) ($chk['weight'] ?? 0)) . '</td>';
            echo '<td><code>' . esc_html((string) ($chk['detail'] ?? '')) . '</code></td>';
            echo '<td>' . esc_html('' !== (string) ($chk['fix_hint'] ?? '') ? (string) $chk['fix_hint'] : '—') . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
        echo '</div>';

        // Step 2: 1-Click PHP Auto-Configuration
        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('2 žingsnis. Automatinis PHP konfigūravimas (1 paspaudimas, be SSH)', 'gratis-security') . '</h2>';
        echo '<p style="margin:0 0 12px 0; color:#50575e; font-size:13px;">';
        echo esc_html__('Paruošia apsaugotą diską, įjungia saugius numatytuosius nustatymus, sinchronizuoja parašus, suplanuoja WP-Cron užduotis, išvalo manifestu patvirtintus FIM pranešimus ir atlieka pradinį nuskaitymą.', 'gratis-security');
        echo '</p>';

        echo '<div class="gs-toolbar">';
        echo '<label for="gs-wiz-waf-mode" style="font-weight:600;">' . esc_html__('Užklausų režimas:', 'gratis-security') . '</label>';
        echo '<select id="gs-wiz-waf-mode">';
        echo '<option value="monitor"' . selected($waf_mode, 'monitor', false) . '>' . esc_html__('Stebėti ir registruoti — saugus numatytasis', 'gratis-security') . '</option>';
        echo '<option value="block"' . selected($waf_mode, 'block', false) . '>' . esc_html__('Aktyvus blokavimas + auto-ban', 'gratis-security') . '</option>';
        echo '</select>';

        echo '<label style="display:inline-flex; align-items:center; gap:5px; font-size:13px;">';
        echo '<input type="checkbox" id="gs-wiz-sync-wp" checked> ';
        echo esc_html__('Atnaujinti parašus ir WordPress.org kontrolines sumas', 'gratis-security');
        echo '</label>';

        echo '<label style="display:inline-flex; align-items:center; gap:5px; font-size:13px;">';
        echo '<input type="checkbox" id="gs-wiz-run-scans" checked> ';
        echo esc_html__('Atlikti pradinę failų ir kenkėjiško kodo patikrą', 'gratis-security');
        echo '</label>';
        echo '</div>';

        echo '<div class="gs-toolbar">';
        echo '<button type="button" id="gs-wiz-run-btn" class="button button-primary button-hero">' . esc_html__('Automatiškai sukonfigūruoti viską per PHP', 'gratis-security') . '</button>';
        echo '<span id="gs-wiz-spinner" class="spinner" style="float:none; margin:0;"></span>';
        echo '<span id="gs-wiz-msg" class="gs-msg"></span>';
        echo '</div>';

        echo '<div id="gs-wiz-results" style="margin-top:10px;"></div>';
        echo '</div>';

        // Step 3: Active Protection Summary
        $cron_hooks = [
            'FIM skenavimas'        => FileIntegrity::CRON_HOOK,
            'Žurnalų sekimas'      => EventMonitor::CRON_HOOK,
            'Malware skenavimas'   => MalwareScanner::CRON_HOOK,
            'Parašų atnaujinimas'  => SignatureFeed::CRON_HOOK,
        ];
        $scheduled_count = 0;
        if (function_exists('wp_next_scheduled')) {
            foreach ($cron_hooks as $hook) {
                if (wp_next_scheduled($hook)) {
                    ++$scheduled_count;
                }
            }
        }

        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('3 žingsnis. Aktyvi apsauga', 'gratis-security') . '</h2>';
        echo '<div id="gs-wiz-active-grid" class="gs-stepper">';

        echo '<div class="gs-step-box">';
        echo '<strong>' . esc_html__('Failų stebėjimas (FIM)', 'gratis-security') . '</strong><br>';
        echo '<span class="gs-badge ' . esc_attr($fim_on ? 'gs-badge-ok' : 'gs-badge-warn') . '">' . esc_html($fim_on ? 'Aktyvu' : 'Išjungta') . '</span> ';
        echo '<span style="font-size:12px; color:#50575e;">' . esc_html(sprintf('Atviri incidentai: %d', (int) ($det_counts['open'] ?? 0))) . '</span>';
        echo '</div>';

        echo '<div class="gs-step-box">';
        echo '<strong>' . esc_html__('Kenkėjiško kodo skeneris', 'gratis-security') . '</strong><br>';
        $mw_cnt = $malware ? count((array) ($malware['findings'] ?? [])) : 0;
        echo '<span class="gs-badge ' . esc_attr($mal_cron_on ? 'gs-badge-ok' : 'gs-badge-warn') . '">' . esc_html($mal_cron_on ? 'Dienos cron' : 'Rankinis') . '</span> ';
        echo '<span style="font-size:12px; color:#50575e;">' . esc_html($malware ? sprintf('Radiniai: %d', $mw_cnt) : 'Dar nenuskaityta') . '</span>';
        echo '</div>';

        echo '<div class="gs-step-box">';
        echo '<strong>' . esc_html__('Užklausos ir WAF', 'gratis-security') . '</strong><br>';
        echo '<span class="gs-badge ' . esc_attr(UiHelpers::badge_class($waf_mode)) . '">' . esc_html(strtoupper($waf_mode)) . '</span> ';
        echo '<span style="font-size:12px; color:#50575e;">' . esc_html(sprintf('24 val.: %d | Banai: %d', (int) ($req_counts['last_24h'] ?? 0), (int) ($req_counts['active_bans'] ?? 0))) . '</span>';
        echo '</div>';

        echo '<div class="gs-step-box">';
        echo '<strong>' . esc_html__('Parašai ir WP-Cron', 'gratis-security') . '</strong><br>';
        echo '<span class="gs-badge ' . esc_attr($sig_cron_on ? 'gs-badge-ok' : 'gs-badge-warn') . '">' . esc_html((string) ($signatures['version'] ?? SignatureFeed::BUILTIN_VERSION)) . '</span> ';
        echo '<span style="font-size:12px; color:#50575e;">' . esc_html(sprintf('Cron užduotys: %d / %d', $scheduled_count, count($cron_hooks))) . '</span>';
        echo '</div>';

        echo '</div>';
        echo '</div>';

        // Step 4: Optional OS-Level Hardening (collapsed secondary section)
        echo '<details class="gs-collapsible">';
        echo '<summary>' . esc_html__('4 žingsnis. Papildomas OS lygio sustiprinimas (nebūtina, po vedlio)', 'gratis-security') . '</summary>';
        echo '<p style="margin:10px 0 8px 0; font-size:13px; color:#50575e;">';
        echo esc_html(sprintf(
            'Šios komandos papildo PHP apsaugą OS branduolio lygiu: auditd reikalauja root (CAP_AUDIT_CONTROL), kad pažeistas PHP negalėtų keisti žurnalų; gratis-fim.service paleidžia inotifywait kaip %s:%s su minimalia CPU apkrova; ClamAV tikrina dvejetainius ir archyvų failus.',
            $runtime_user,
            $runtime_grp
        ));
        echo '</p>';

        echo '<div class="gs-toolbar">';
        echo '<label for="gs-wiz-svc-mode" style="font-weight:600;">' . esc_html__('Serviso vartotojas:', 'gratis-security') . '</label>';
        echo '<select id="gs-wiz-svc-mode">';
        echo '<option value="php" selected>' . esc_html(sprintf('PHP vartotojas (%s:%s) — rekomenduojama', $runtime_user, $runtime_grp)) . '</option>';
        echo '<option value="root">' . esc_html__('root — tik skaitymui PHP (/var/log/gratis-fim.jsonl)', 'gratis-security') . '</option>';
        echo '</select>';
        echo '<span id="gs-wiz-os-spinner" class="spinner" style="float:none; margin:0;"></span>';
        echo '</div>';

        echo '<div id="gs-wiz-os-steps">';
        self::render_os_upgrade_blocks($recs);
        echo '</div>';
        echo '</details>';

        UiHelpers::render_copy_helper_js();
        self::render_js($nonce);
    }

    /**
     * Render OS-level command blocks for steps requiring action or manual verification.
     *
     * @param array<string,mixed> $recs
     */
    private static function render_os_upgrade_blocks(array $recs): void {
        $steps         = (array) ($recs['steps'] ?? []);
        $action_cmds   = [];
        $rendered_any  = false;

        foreach ($steps as $step) {
            if (!is_array($step)) {
                continue;
            }
            $status = (string) ($step['status'] ?? 'optional');
            $cmd    = trim((string) ($step['command'] ?? ''));
            if ('' === $cmd || 'done' === $status) {
                continue;
            }
            $rendered_any = true;
            $title = (string) ($step['title'] ?? 'OS komanda');
            $note  = (string) ($step['reason'] ?? $step['note'] ?? '');

            echo '<div style="margin-top:12px;">';
            echo '<div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">';
            echo '<strong>' . esc_html($title) . '</strong>';
            echo '<span class="gs-badge ' . esc_attr(UiHelpers::badge_class($status)) . '">' . esc_html($status) . '</span>';
            echo '</div>';
            if ('' !== $note) {
                echo '<p style="margin:4px 0; font-size:12px; color:#50575e;">' . esc_html($note) . '</p>';
            }
            UiHelpers::render_code_block($title, $cmd);
            echo '</div>';

            if (in_array($status, ['action_needed', 'manual_verify'], true)) {
                $action_cmds[] = "# {$title}\n{$cmd}";
            }
        }

        if (!empty($action_cmds)) {
            $combined = "#!/usr/bin/env bash\nset -euo pipefail\n\n" . implode("\n\n", $action_cmds);
            echo '<div style="margin-top:14px;">';
            UiHelpers::render_code_block(__('Bendra vieno paleidimo komanda (Combined Script)', 'gratis-security'), $combined);
            echo '</div>';
        } elseif (!$rendered_any) {
            echo '<p style="margin:8px 0 0 0; font-size:13px; color:#00a32a;">' . esc_html__('Visos OS lygio priemonės jau aktyvios arba nereikalauja veiksmų.', 'gratis-security') . '</p>';
        }
    }

    /**
     * Render safe DOM JS for the Wizard tab.
     */
    private static function render_js(string $nonce): void {
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

            function renderAudit(audit) {
                if (!audit) return;
                var score = Number(audit.score || 0);
                var grade = String(audit.grade || 'F');
                var circle = document.getElementById('gs-wiz-score-circle');
                var valEl = document.getElementById('gs-wiz-score-val');
                var gradeEl = document.getElementById('gs-wiz-score-grade');
                if (circle) circle.style.background = score >= 80 ? '#00a32a' : (score >= 60 ? '#dba617' : '#d63638');
                if (valEl) valEl.textContent = String(score);
                if (gradeEl) gradeEl.textContent = 'Įvertis ' + grade + ' / 100';

                var tbody = document.getElementById('gs-wiz-audit-body');
                if (!tbody || !Array.isArray(audit.checks)) return;
                clearNode(tbody);
                audit.checks.forEach(function(chk) {
                    var tr = document.createElement('tr');
                    var st = String(chk.status || 'fail');
                    var lbl = st === 'pass' ? 'Atitinka' : (st === 'warn' ? 'Įspėjimas' : 'Trūksta');
                    var tdSt = document.createElement('td');
                    tdSt.appendChild(el('span', lbl, badgeCls(st)));
                    var tdLbl = document.createElement('td');
                    tdLbl.appendChild(el('strong', String(chk.label || '')));
                    var tdW = el('td', String(chk.weight || 0));
                    var tdDet = document.createElement('td');
                    tdDet.appendChild(el('code', String(chk.detail || '')));
                    var tdFix = el('td', chk.fix_hint ? String(chk.fix_hint) : '—');
                    tr.appendChild(tdSt);
                    tr.appendChild(tdLbl);
                    tr.appendChild(tdW);
                    tr.appendChild(tdDet);
                    tr.appendChild(tdFix);
                    tbody.appendChild(tr);
                });
            }

            function renderCodeBlockDom(parent, title, code) {
                var wrap = el('div', null, 'gs-code-wrap');
                var head = el('div', null, 'gs-code-head');
                head.appendChild(el('span', title));
                var btn = el('button', 'Kopijuoti', 'button button-small gratis-copy-btn');
                btn.type = 'button';
                btn.setAttribute('data-copy', code);
                head.appendChild(btn);
                var pre = el('pre', code, 'gs-code-pre');
                wrap.appendChild(head);
                wrap.appendChild(pre);
                parent.appendChild(wrap);
            }

            var runBtn = document.getElementById('gs-wiz-run-btn');
            var spinner = document.getElementById('gs-wiz-spinner');
            var msgEl = document.getElementById('gs-wiz-msg');
            var resultsBox = document.getElementById('gs-wiz-results');
            var modeSel = document.getElementById('gs-wiz-waf-mode');
            var syncWp = document.getElementById('gs-wiz-sync-wp');
            var runScans = document.getElementById('gs-wiz-run-scans');

            if (runBtn) {
                runBtn.addEventListener('click', function() {
                    runBtn.disabled = true;
                    if (spinner) spinner.classList.add('is-active');
                    if (msgEl) {
                        msgEl.style.color = '#2271b1';
                        msgEl.textContent = 'Vykdoma PHP konfigūracija...';
                    }

                    postAjax('gratis_wizard_autoconfig', {
                        waf_mode: modeSel ? modeSel.value : 'monitor',
                        sync_wp_checksums: (syncWp && syncWp.checked) ? '1' : '0',
                        run_scans: (runScans && runScans.checked) ? '1' : '0'
                    }).then(function(res) {
                        if (!res || !res.success || !res.data) {
                            if (msgEl) {
                                msgEl.style.color = '#d63638';
                                msgEl.textContent = (res && res.data && res.data.message) ? res.data.message : 'Konfigūravimas nepavyko.';
                            }
                            return;
                        }
                        var data = res.data;
                        renderAudit(data.audit);

                        var compBadge = document.getElementById('gs-wiz-completed-badge');
                        var compAt = document.getElementById('gs-wiz-completed-at');
                        if (compBadge) {
                            compBadge.className = 'gs-badge gs-badge-ok';
                            compBadge.textContent = 'Sukonfigūruota';
                        }
                        if (compAt && data.completed_at) {
                            compAt.textContent = data.completed_at;
                        }

                        if (msgEl) {
                            msgEl.style.color = '#00a32a';
                            msgEl.textContent = 'PHP konfigūracija baigta! Naujas įvertis: ' + ((data.audit && data.audit.score) || 0) + '/100.';
                        }

                        if (resultsBox && data.steps) {
                            clearNode(resultsBox);
                            var labels = {
                                storage: 'Apsaugota saugykla ir fim-events.jsonl',
                                settings: 'Saugūs PHP numatytieji nustatymai',
                                signatures: 'Parašų rinkinys diske',
                                cron: 'WP-Cron užduotys',
                                cleanup: 'Išvalyti manifestu patvirtinti FIM įrašai',
                                fim_scan: 'Pradinė FIM patikra',
                                malware_scan: 'Pradinė kenkėjiško kodo patikra'
                            };
                            var tbl = el('table', null, 'widefat striped');
                            var tb = document.createElement('tbody');
                            Object.keys(data.steps).forEach(function(key) {
                                var st = data.steps[key] || {};
                                var tr = document.createElement('tr');
                                var tdName = document.createElement('td');
                                tdName.appendChild(el('strong', labels[key] || key));
                                var tdStatus = document.createElement('td');
                                tdStatus.appendChild(el('span', st.skipped ? 'Praleista' : (st.ok ? 'Atlikta' : 'Klaida'), badgeCls(st.skipped ? 'warn' : (st.ok ? 'ok' : 'fail'))));
                                var tdInfo = el('td', JSON.stringify(st));
                                tdInfo.style.fontSize = '12px';
                                tr.appendChild(tdName);
                                tr.appendChild(tdStatus);
                                tr.appendChild(tdInfo);
                                tb.appendChild(tr);
                            });
                            tbl.appendChild(tb);
                            resultsBox.appendChild(tbl);
                        }
                    }).catch(function() {
                        if (msgEl) {
                            msgEl.style.color = '#d63638';
                            msgEl.textContent = 'Tinklo klaida vykdant vedlį.';
                        }
                    }).finally(function() {
                        runBtn.disabled = false;
                        if (spinner) spinner.classList.remove('is-active');
                    });
                });
            }

            var svcMode = document.getElementById('gs-wiz-svc-mode');
            var osSpinner = document.getElementById('gs-wiz-os-spinner');
            var osSteps = document.getElementById('gs-wiz-os-steps');
            if (svcMode) {
                svcMode.addEventListener('change', function() {
                    if (osSpinner) osSpinner.classList.add('is-active');
                    postAjax('gratis_wizard_diagnose', {
                        service_user_mode: svcMode.value
                    }).then(function(res) {
                        if (!res || !res.success || !res.data || !osSteps) return;
                        var recs = (res.data.server && res.data.server.recommendations) ? res.data.server.recommendations : {};
                        var steps = Array.isArray(recs.steps) ? recs.steps : [];
                        clearNode(osSteps);
                        var combined = [];
                        steps.forEach(function(step) {
                            var st = String(step.status || 'optional');
                            var cmd = String(step.command || '').trim();
                            if (!cmd || st === 'done') return;
                            var box = el('div');
                            box.style.marginTop = '12px';
                            var hdr = el('div');
                            hdr.style.display = 'flex';
                            hdr.style.justifyContent = 'space-between';
                            hdr.style.alignItems = 'center';
                            hdr.appendChild(el('strong', String(step.title || 'OS komanda')));
                            hdr.appendChild(el('span', st, badgeCls(st)));
                            box.appendChild(hdr);
                            if (step.reason || step.note) {
                                var p = el('p', String(step.reason || step.note));
                                p.style.margin = '4px 0';
                                p.style.fontSize = '12px';
                                p.style.color = '#50575e';
                                box.appendChild(p);
                            }
                            renderCodeBlockDom(box, String(step.title || 'Komanda'), cmd);
                            osSteps.appendChild(box);
                            if (st === 'action_needed' || st === 'manual_verify') {
                                combined.push('# ' + (step.title || '') + '\n' + cmd);
                            }
                        });
                        if (combined.length) {
                            var cWrap = el('div');
                            cWrap.style.marginTop = '14px';
                            renderCodeBlockDom(cWrap, 'Bendra vieno paleidimo komanda (Combined Script)', '#!/usr/bin/env bash\nset -euo pipefail\n\n' + combined.join('\n\n'));
                            osSteps.appendChild(cWrap);
                        } else if (!osSteps.firstChild) {
                            var okMsg = el('p', 'Visos OS lygio priemonės jau aktyvios arba nereikalauja veiksmų.');
                            okMsg.style.color = '#00a32a';
                            osSteps.appendChild(okMsg);
                        }
                    }).finally(function() {
                        if (osSpinner) osSpinner.classList.remove('is-active');
                    });
                });
            }
        });
        </script>
        <?php
    }
}
