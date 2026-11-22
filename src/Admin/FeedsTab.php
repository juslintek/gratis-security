<?php declare(strict_types=1);

namespace Gratis\Security\Admin;

use Gratis\Security\FileIntegrity;
use Gratis\Security\Settings;
use Gratis\Security\SignatureFeed;

defined('ABSPATH') || exit;

/**
 * Threat Intelligence & Signature Subscriptions tab renderer.
 */
final class FeedsTab {

    /**
     * Render the Threat Intelligence & Signature Feeds tab.
     */
    public static function render(string $nonce): void {
        $status   = SignatureFeed::get_status();
        $settings = Settings::all();
        $counts   = (array) ($status['counts'] ?? []);
        $sources  = (array) ($status['sources'] ?? []);

        $wp_checksums_cached = self::has_cached_wp_checksums();
        $wp_src_status       = (string) ($sources['wp_checksums']['status'] ?? '');
        $wp_cache_label      = $wp_checksums_cached
            ? __('Išsaugota diske', 'gratis-security')
            : (('ok' === $wp_src_status) ? __('Sinchronizuota', 'gratis-security') : __('Dar nesinchronizuota', 'gratis-security'));

        // KPI strip
        echo '<div class="gs-kpi-grid">';

        echo '<div class="gs-kpi-card">';
        echo '<div class="gs-kpi-label">' . esc_html__('Parašų rinkinio versija', 'gratis-security') . '</div>';
        echo '<div id="gs-feeds-kpi-ver" class="gs-kpi-value">' . esc_html((string) ($status['version'] ?? SignatureFeed::BUILTIN_VERSION)) . '</div>';
        echo '<div id="gs-feeds-kpi-updated" class="gs-kpi-sub">' . esc_html(!empty($status['last_updated']) ? (string) $status['last_updated'] : 'Dar nesinchronizuota') . '</div>';
        echo '</div>';

        echo '<div class="gs-kpi-card">';
        echo '<div class="gs-kpi-label">' . esc_html__('Kenkėjiško kodo taisyklės', 'gratis-security') . '</div>';
        echo '<div id="gs-feeds-kpi-mw" class="gs-kpi-value">' . esc_html((string) (int) ($counts['malware_rules'] ?? 0)) . '</div>';
        echo '</div>';

        echo '<div class="gs-kpi-card">';
        echo '<div class="gs-kpi-label">' . esc_html__('WAF užklausų taisyklės', 'gratis-security') . '</div>';
        echo '<div id="gs-feeds-kpi-req" class="gs-kpi-value">' . esc_html((string) (int) ($counts['request_rules'] ?? 0)) . '</div>';
        echo '</div>';

        echo '<div class="gs-kpi-card">';
        echo '<div class="gs-kpi-label">' . esc_html__('Blogi SHA-256 / Feed IP', 'gratis-security') . '</div>';
        echo '<div id="gs-feeds-kpi-hashes" class="gs-kpi-value">' . esc_html(sprintf('%d / %d', (int) ($counts['bad_hashes'] ?? 0), (int) ($counts['blocked_ips'] ?? 0))) . '</div>';
        echo '</div>';

        echo '<div class="gs-kpi-card">';
        echo '<div class="gs-kpi-label">' . esc_html__('WP Core kontrolinės sumos', 'gratis-security') . '</div>';
        echo '<div id="gs-feeds-kpi-wp" class="gs-kpi-value" style="font-size:14px;">';
        echo '<span class="gs-badge ' . esc_attr($wp_checksums_cached ? 'gs-badge-ok' : 'gs-badge-warn') . '">' . esc_html($wp_cache_label) . '</span>';
        echo '</div>';
        echo '</div>';

        echo '</div>';

        // Update Now + Source Status Card
        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('Sinchronizacija ir šaltinių būsena', 'gratis-security') . '</h2>';
        echo '<div class="gs-toolbar">';
        echo '<button type="button" id="gs-feeds-update-btn" class="button button-primary">' . esc_html__('Atnaujinti parašus dabar', 'gratis-security') . '</button>';
        echo '<span id="gs-feeds-update-spinner" class="spinner" style="float:none; margin:0;"></span>';
        echo '<span id="gs-feeds-update-msg" class="gs-msg"></span>';
        echo '</div>';

        echo '<table class="widefat striped">';
        echo '<thead><tr><th style="width:200px;">' . esc_html__('Šaltinis', 'gratis-security') . '</th><th style="width:120px;">' . esc_html__('Būsena', 'gratis-security') . '</th><th>' . esc_html__('Išsami informacija', 'gratis-security') . '</th></tr></thead>';
        echo '<tbody id="gs-feeds-sources-body">';
        self::render_source_rows($sources);
        echo '</tbody></table>';
        echo '</div>';

        // Subscription Settings Form Card
        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('Išorinių grėsmių srautų (Feeds) nustatymai', 'gratis-security') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';

        echo '<tr><th scope="row">' . esc_html__('Automatinis atnaujinimas', 'gratis-security') . '</th><td>';
        echo '<label><input type="checkbox" id="gs-feed-auto-update" value="1"' . checked((int) ($settings['signature_auto_update'] ?? 1), 1, false) . '> ';
        echo esc_html__('Kasdien automatiškai atnaujinti parašus per WP-Cron', 'gratis-security') . '</label>';
        echo '</td></tr>';

        echo '<tr><th scope="row">' . esc_html__('WordPress.org kontrolinės sumos', 'gratis-security') . '</th><td>';
        echo '<label><input type="checkbox" id="gs-feed-sync-wp" value="1"' . checked((int) ($settings['sync_wp_checksums'] ?? 1), 1, false) . '> ';
        echo esc_html__('Sinchronizuoti oficialias WordPress.org Core kontrolines sumas', 'gratis-security') . '</label>';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="gs-feed-url">' . esc_html__('Custom JSON Signature Feed URL', 'gratis-security') . '</label></th><td>';
        echo '<input type="url" id="gs-feed-url" class="regular-text" placeholder="https://example.com/signatures.json" value="' . esc_attr((string) ($settings['signature_feed_url'] ?? '')) . '">';
        echo '<p class="description">' . esc_html__('Privalo naudoti HTTPS. Grąžina JSON paketą su malware_rules, request_rules, bad_hashes ir blocked_ips.', 'gratis-security') . '</p>';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="gs-feed-token">' . esc_html__('Feed API Token / Bearer Key', 'gratis-security') . '</label></th><td>';
        echo '<input type="password" id="gs-feed-token" class="regular-text" autocomplete="new-password" value="' . esc_attr((string) ($settings['signature_feed_token'] ?? '')) . '">';
        echo '<p class="description">' . esc_html__('Nebūtinas raktas, siunčiamas kaip Authorization: Bearer ir X-API-Key antraštės.', 'gratis-security') . '</p>';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="gs-ip-feed-url">' . esc_html__('Išorinio IP blokavimo srauto URL', 'gratis-security') . '</label></th><td>';
        echo '<input type="url" id="gs-ip-feed-url" class="regular-text" placeholder="https://example.com/blocklist.txt" value="' . esc_attr((string) ($settings['ip_feed_url'] ?? '')) . '">';
        echo '<p class="description">' . esc_html__('Privalo naudoti HTTPS. Paprastas tekstinis IPv4/IPv6/CIDR sąrašas po vieną įrašą eilutėje.', 'gratis-security') . '</p>';
        echo '</td></tr>';

        echo '</tbody></table>';

        echo '<div class="gs-toolbar" style="margin-bottom:0;">';
        echo '<button type="button" id="gs-feeds-save-btn" class="button button-primary">' . esc_html__('Išsaugoti šaltinių nustatymus', 'gratis-security') . '</button>';
        echo '<span id="gs-feeds-save-spinner" class="spinner" style="float:none; margin:0;"></span>';
        echo '<span id="gs-feeds-save-msg" class="gs-msg"></span>';
        echo '</div>';
        echo '</div>';

        self::render_js($nonce);
    }

    /**
     * Check whether WP Core checksums cache JSON exists in storage.
     */
    private static function has_cached_wp_checksums(): bool {
        $dir = FileIntegrity::get_storage_dir();
        if (!@is_dir($dir)) {
            return false;
        }
        $matches = @glob($dir . '/' . FileIntegrity::CORE_CACHE_PREFIX . '*.json');
        return is_array($matches) && !empty($matches);
    }

    /**
     * Render source status rows.
     *
     * @param array<string,mixed> $sources
     */
    private static function render_source_rows(array $sources): void {
        $labels = [
            'builtin'        => __('Integruotas rinkinys (Built-in)', 'gratis-security'),
            'wp_checksums'   => __('WordPress.org Core kontrolinės sumos', 'gratis-security'),
            'signature_feed' => __('Custom JSON Signature Feed', 'gratis-security'),
            'ip_feed'        => __('Išorinis IP blokavimo srautas', 'gratis-security'),
        ];

        foreach ($labels as $key => $title) {
            $src = isset($sources[$key]) && is_array($sources[$key]) ? $sources[$key] : ['status' => 'skipped', 'reason' => 'not_synced'];
            $st  = (string) ($src['status'] ?? 'skipped');
            $cls = ('ok' === $st) ? 'gs-badge-ok' : (('error' === $st) ? 'gs-badge-danger' : 'gs-badge-muted');
            $details = [];
            foreach ($src as $dk => $dv) {
                if ('status' === $dk) {
                    continue;
                }
                $details[] = $dk . ': ' . (is_scalar($dv) ? (string) $dv : wp_json_encode($dv));
            }
            echo '<tr>';
            echo '<td><strong>' . esc_html($title) . '</strong></td>';
            echo '<td><span class="gs-badge ' . esc_attr($cls) . '">' . esc_html(strtoupper($st)) . '</span></td>';
            echo '<td><code>' . esc_html(!empty($details) ? implode(' | ', $details) : '—') . '</code></td>';
            echo '</tr>';
        }
    }

    /**
     * Render safe DOM JS for Signature Feeds.
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

            function postAjax(action, params) {
                var fd = new FormData();
                fd.append('action', action);
                fd.append('nonce', nonce);
                Object.keys(params || {}).forEach(function(k) {
                    fd.append(k, params[k]);
                });
                return fetch(ajaxEndpoint, { method: 'POST', body: fd }).then(function(r) { return r.json(); });
            }

            function renderSources(sources) {
                var tbody = document.getElementById('gs-feeds-sources-body');
                if (!tbody) return;
                clearNode(tbody);
                var labels = {
                    builtin: 'Integruotas rinkinys (Built-in)',
                    wp_checksums: 'WordPress.org Core kontrolinės sumos',
                    signature_feed: 'Custom JSON Signature Feed',
                    ip_feed: 'Išorinis IP blokavimo srautas'
                };
                Object.keys(labels).forEach(function(k) {
                    var src = (sources && sources[k]) ? sources[k] : { status: 'skipped', reason: 'not_synced' };
                    var st = String(src.status || 'skipped');
                    var cls = st === 'ok' ? 'gs-badge gs-badge-ok' : (st === 'error' ? 'gs-badge gs-badge-danger' : 'gs-badge gs-badge-muted');
                    var details = [];
                    Object.keys(src).forEach(function(dk) {
                        if (dk !== 'status') details.push(dk + ': ' + String(src[dk]));
                    });
                    var tr = document.createElement('tr');
                    var tdN = document.createElement('td');
                    tdN.appendChild(el('strong', labels[k]));
                    var tdS = document.createElement('td');
                    tdS.appendChild(el('span', st.toUpperCase(), cls));
                    var tdD = document.createElement('td');
                    tdD.appendChild(el('code', details.length ? details.join(' | ') : '—'));
                    tr.appendChild(tdN);
                    tr.appendChild(tdS);
                    tr.appendChild(tdD);
                    tbody.appendChild(tr);
                });
            }

            var updateBtn = document.getElementById('gs-feeds-update-btn');
            var updateSpin = document.getElementById('gs-feeds-update-spinner');
            var updateMsg = document.getElementById('gs-feeds-update-msg');

            if (updateBtn) {
                updateBtn.addEventListener('click', function() {
                    updateBtn.disabled = true;
                    if (updateSpin) updateSpin.classList.add('is-active');
                    if (updateMsg) {
                        updateMsg.style.color = '#2271b1';
                        updateMsg.textContent = 'Sinchronizuojami parašai...';
                    }
                    postAjax('gratis_signatures_update', {}).then(function(res) {
                        if (!res || !res.success || !res.data) {
                            if (updateMsg) {
                                updateMsg.style.color = '#d63638';
                                updateMsg.textContent = (res && res.data && res.data.message) ? res.data.message : 'Sinchronizacija nepavyko.';
                            }
                            return;
                        }
                        var d = res.data;
                        var cnt = d.counts || {};
                        var verEl = document.getElementById('gs-feeds-kpi-ver');
                        var updEl = document.getElementById('gs-feeds-kpi-updated');
                        var mwEl = document.getElementById('gs-feeds-kpi-mw');
                        var reqEl = document.getElementById('gs-feeds-kpi-req');
                        var hashEl = document.getElementById('gs-feeds-kpi-hashes');
                        if (verEl) verEl.textContent = String(d.version || '');
                        if (updEl) updEl.textContent = String(d.last_updated || '');
                        if (mwEl) mwEl.textContent = String(cnt.malware_rules || 0);
                        if (reqEl) reqEl.textContent = String(cnt.request_rules || 0);
                        if (hashEl) hashEl.textContent = String(cnt.bad_hashes || 0) + ' / ' + String(cnt.blocked_ips || 0);

                        if (d.sources && d.sources.wp_checksums) {
                            var wpEl = document.getElementById('gs-feeds-kpi-wp');
                            if (wpEl) {
                                clearNode(wpEl);
                                var wpOk = d.sources.wp_checksums.status === 'ok';
                                wpEl.appendChild(el('span', wpOk ? 'Sinchronizuota' : String(d.sources.wp_checksums.status || 'Praleista'), wpOk ? 'gs-badge gs-badge-ok' : 'gs-badge gs-badge-warn'));
                            }
                        }

                        renderSources(d.sources || {});
                        if (updateMsg) {
                            updateMsg.style.color = '#00a32a';
                            updateMsg.textContent = 'Parašai sėkmingai atnaujinti.';
                        }
                    }).catch(function() {
                        if (updateMsg) {
                            updateMsg.style.color = '#d63638';
                            updateMsg.textContent = 'Tinklo klaida atnaujinant parašus.';
                        }
                    }).finally(function() {
                        updateBtn.disabled = false;
                        if (updateSpin) updateSpin.classList.remove('is-active');
                    });
                });
            }

            var saveBtn = document.getElementById('gs-feeds-save-btn');
            var saveSpin = document.getElementById('gs-feeds-save-spinner');
            var saveMsg = document.getElementById('gs-feeds-save-msg');
            if (saveBtn) {
                saveBtn.addEventListener('click', function() {
                    saveBtn.disabled = true;
                    if (saveSpin) saveSpin.classList.add('is-active');
                    var autoCb = document.getElementById('gs-feed-auto-update');
                    var wpCb = document.getElementById('gs-feed-sync-wp');
                    var urlEl = document.getElementById('gs-feed-url');
                    var tokEl = document.getElementById('gs-feed-token');
                    var ipEl = document.getElementById('gs-ip-feed-url');

                    postAjax('gratis_signatures_save_feeds', {
                        signature_auto_update: (autoCb && autoCb.checked) ? '1' : '0',
                        sync_wp_checksums: (wpCb && wpCb.checked) ? '1' : '0',
                        signature_feed_url: urlEl ? urlEl.value.trim() : '',
                        signature_feed_token: tokEl ? tokEl.value.trim() : '',
                        ip_feed_url: ipEl ? ipEl.value.trim() : ''
                    }).then(function(res) {
                        if (!res || !res.success) {
                            if (saveMsg) {
                                saveMsg.style.color = '#d63638';
                                saveMsg.textContent = (res && res.data && res.data.message) ? res.data.message : 'Nepavyko išsaugoti.';
                            }
                            return;
                        }
                        if (saveMsg) {
                            saveMsg.style.color = '#00a32a';
                            saveMsg.textContent = 'Nustatymai išsaugoti.';
                        }
                    }).catch(function() {
                        if (saveMsg) {
                            saveMsg.style.color = '#d63638';
                            saveMsg.textContent = 'Tinklo klaida išsaugant nustatymus.';
                        }
                    }).finally(function() {
                        saveBtn.disabled = false;
                        if (saveSpin) saveSpin.classList.remove('is-active');
                    });
                });
            }
        });
        </script>
        <?php
    }
}
