<?php declare(strict_types=1);

namespace Gratis\Security\Admin;

use Gratis\Security\RequestGuard;

defined('ABSPATH') || exit;

/**
 * Malicious Requests, WAF Mode, and IP Blocklist/Allowlist/Auto-Ban tab renderer.
 */
final class RequestsTab {

    private const PER_PAGE = 25;

    /**
     * Render the Malicious Requests & WAF tab.
     */
    public static function render(string $nonce): void {
        $data        = RequestGuard::query_requests(['page' => 1, 'per_page' => self::PER_PAGE]);
        $ip_rules    = RequestGuard::get_ip_rules();
        $active_bans = RequestGuard::get_active_bans();
        $mode        = RequestGuard::get_mode();

        $counts    = (array) ($data['counts'] ?? []);
        $rows      = (array) ($data['requests'] ?? []);
        $top_ips   = (array) ($data['top_ips'] ?? []);
        $tot_filt  = (int) ($data['total_filtered'] ?? count($rows));
        $tot_pages = (int) ($data['total_pages'] ?? 1);
        $allowlist = (array) ($ip_rules['allowlist'] ?? []);
        $blocklist = (array) ($ip_rules['blocklist'] ?? []);

        // KPI strip
        echo '<div class="gs-kpi-grid">';

        echo '<div class="gs-kpi-card">';
        echo '<div class="gs-kpi-label">' . esc_html__('WAF režimas', 'gratis-security') . '</div>';
        echo '<div class="gs-kpi-value"><span class="gs-badge ' . esc_attr(UiHelpers::badge_class('block' === $mode ? 'ok' : ('monitor' === $mode ? 'info' : 'warn'))) . '">' . esc_html(strtoupper($mode)) . '</span></div>';
        echo '</div>';

        echo '<div class="gs-kpi-card">';
        echo '<div class="gs-kpi-label">' . esc_html__('Grėsmės (24 val.)', 'gratis-security') . '</div>';
        echo '<div id="gs-req-kpi-24h" class="gs-kpi-value">' . esc_html((string) (int) ($counts['last_24h'] ?? 0)) . '</div>';
        echo '<div id="gs-req-kpi-total" class="gs-kpi-sub">' . esc_html(sprintf('Iš viso žurnale: %d', (int) ($counts['total'] ?? 0))) . '</div>';
        echo '</div>';

        echo '<div class="gs-kpi-card">';
        echo '<div class="gs-kpi-label">' . esc_html__('Blokuota / Registruota', 'gratis-security') . '</div>';
        echo '<div id="gs-req-kpi-actions" class="gs-kpi-value">' . esc_html(sprintf('%d / %d', (int) ($counts['blocked'] ?? 0), (int) ($counts['logged'] ?? 0))) . '</div>';
        echo '</div>';

        echo '<div class="gs-kpi-card">';
        echo '<div class="gs-kpi-label">' . esc_html__('Aktyvūs auto-banai', 'gratis-security') . '</div>';
        echo '<div id="gs-req-kpi-bans" class="gs-kpi-value">' . esc_html((string) count($active_bans)) . '</div>';
        echo '</div>';

        echo '<div class="gs-kpi-card">';
        echo '<div class="gs-kpi-label">' . esc_html__('Rankinės IP taisyklės', 'gratis-security') . '</div>';
        echo '<div id="gs-req-kpi-rules" class="gs-kpi-value">' . esc_html(sprintf('%d blokuoti / %d leisti', count($blocklist), count($allowlist))) . '</div>';
        echo '</div>';

        echo '</div>';

        // Top attacking IPs (24h)
        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('Aktyviausi atakuojantys IP (24 val.)', 'gratis-security') . '</h2>';
        echo '<div id="gs-req-top-ips" class="gs-pills">';
        if (empty($top_ips)) {
            echo '<span style="font-size:12px; color:#646970;">' . esc_html__('Per pastarąsias 24 val. įtartinų IP neužfiksuota.', 'gratis-security') . '</span>';
        } else {
            foreach ($top_ips as $tip) {
                $ip_str  = (string) ($tip['ip'] ?? '');
                $hit_cnt = (int) ($tip['count'] ?? 0);
                $blocked = !empty($tip['blocked']);
                echo '<span class="gs-pill">';
                echo '<code>' . esc_html($ip_str) . '</code>';
                echo '<strong>(' . esc_html((string) $hit_cnt) . ')</strong>';
                if ($blocked) {
                    echo '<span class="gs-badge gs-badge-danger">' . esc_html__('Blokuotas', 'gratis-security') . '</span>';
                } else {
                    echo '<button type="button" class="button button-small gs-req-quick-block" data-ip="' . esc_attr($ip_str) . '">' . esc_html__('Blokuoti IP', 'gratis-security') . '</button>';
                }
                echo '</span>';
            }
        }
        echo '</div>';
        echo '</div>';

        // Requests Log Table Card
        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('Įtartinų ir blokuotų užklausų žurnalas', 'gratis-security') . '</h2>';

        echo '<div class="gs-toolbar">';
        echo '<input type="search" id="gs-req-search" placeholder="' . esc_attr__('Ieškoti IP, URI, User-Agent...', 'gratis-security') . '" style="width:220px;">';

        echo '<select id="gs-req-category">';
        $categories = [
            'all'          => __('Visos kategorijos', 'gratis-security'),
            'sqli'         => 'sqli',
            'xss'          => 'xss',
            'lfi'          => 'lfi',
            'rce'          => 'rce',
            'php_object'   => 'php_object',
            'probe'        => 'probe',
            'scanner'      => 'scanner',
            'xmlrpc'       => 'xmlrpc',
            'bruteforce'   => 'bruteforce',
            'ip_blocklist' => 'ip_blocklist',
            '404_flood'    => '404_flood',
        ];
        foreach ($categories as $k => $lbl) {
            echo '<option value="' . esc_attr($k) . '">' . esc_html($lbl) . '</option>';
        }
        echo '</select>';

        echo '<select id="gs-req-severity">';
        echo '<option value="all">' . esc_html__('Visi sunkumai', 'gratis-security') . '</option>';
        echo '<option value="critical">' . esc_html__('Kritinis', 'gratis-security') . '</option>';
        echo '<option value="high">' . esc_html__('Aukštas', 'gratis-security') . '</option>';
        echo '<option value="medium">' . esc_html__('Vidutinis', 'gratis-security') . '</option>';
        echo '<option value="low">' . esc_html__('Žemas', 'gratis-security') . '</option>';
        echo '</select>';

        echo '<select id="gs-req-action">';
        echo '<option value="all">' . esc_html__('Visi veiksmai', 'gratis-security') . '</option>';
        echo '<option value="blocked">' . esc_html__('Blokuota', 'gratis-security') . '</option>';
        echo '<option value="logged">' . esc_html__('Registruota', 'gratis-security') . '</option>';
        echo '</select>';

        echo '<select id="gs-req-since">';
        echo '<option value="1h">' . esc_html__('1 val.', 'gratis-security') . '</option>';
        echo '<option value="24h">' . esc_html__('24 val.', 'gratis-security') . '</option>';
        echo '<option value="7d">' . esc_html__('7 d.', 'gratis-security') . '</option>';
        echo '<option value="all" selected>' . esc_html__('Visas laikas', 'gratis-security') . '</option>';
        echo '</select>';

        echo '<button type="button" id="gs-req-refresh-btn" class="button button-secondary">' . esc_html__('Atnaujinti', 'gratis-security') . '</button>';
        echo '<button type="button" id="gs-req-clear-btn" class="button button-secondary">' . esc_html__('Išvalyti žurnalą', 'gratis-security') . '</button>';
        echo '<span id="gs-req-spinner" class="spinner" style="float:none; margin:0;"></span>';
        echo '<span id="gs-req-msg" class="gs-msg"></span>';
        echo '</div>';

        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th style="width:145px;">' . esc_html__('Laikas', 'gratis-security') . '</th>';
        echo '<th style="width:125px;">' . esc_html__('IP adresas', 'gratis-security') . '</th>';
        echo '<th>' . esc_html__('Metodas ir URI', 'gratis-security') . '</th>';
        echo '<th style="width:105px;">' . esc_html__('Kategorija', 'gratis-security') . '</th>';
        echo '<th style="width:85px;">' . esc_html__('Sunkumas', 'gratis-security') . '</th>';
        echo '<th style="width:90px;">' . esc_html__('Veiksmas', 'gratis-security') . '</th>';
        echo '<th>' . esc_html__('Fragmentas', 'gratis-security') . '</th>';
        echo '<th style="width:165px;">' . esc_html__('Greiti veiksmai', 'gratis-security') . '</th>';
        echo '</tr></thead>';
        echo '<tbody id="gs-requests-body">';
        if (empty($rows)) {
            echo '<tr><td colspan="8" style="text-align:center; color:#646970; padding:16px;">' . esc_html__('Įtartinų užklausų įrašų nėra.', 'gratis-security') . '</td></tr>';
        } else {
            foreach ($rows as $r) {
                $ip      = (string) ($r['ip'] ?? '');
                $sev     = (string) ($r['severity'] ?? 'medium');
                $act     = (string) ($r['action'] ?? 'logged');
                $method  = (string) ($r['method'] ?? 'GET');
                $uri     = (string) ($r['uri'] ?? '');
                $cat     = (string) ($r['category'] ?? '');
                $snip    = (string) ($r['matched_snippet'] ?? '');
                echo '<tr>';
                echo '<td><span style="font-size:12px;">' . esc_html((string) ($r['time'] ?? '')) . '</span></td>';
                echo '<td><code>' . esc_html($ip) . '</code></td>';
                echo '<td><strong>' . esc_html($method) . '</strong> <code style="word-break:break-all;">' . esc_html($uri) . '</code></td>';
                echo '<td><code>' . esc_html($cat) . '</code></td>';
                echo '<td><span class="gs-badge ' . esc_attr(UiHelpers::badge_class($sev)) . '">' . esc_html(strtoupper($sev)) . '</span></td>';
                echo '<td><span class="gs-badge ' . esc_attr(UiHelpers::badge_class($act)) . '">' . esc_html(strtoupper($act)) . '</span></td>';
                echo '<td><code class="gs-snippet">' . esc_html('' !== $snip ? $snip : '—') . '</code></td>';
                echo '<td style="white-space:nowrap;">';
                if ('' !== $ip) {
                    echo '<button type="button" class="button button-small gs-req-quick-block" data-ip="' . esc_attr($ip) . '" style="margin-right:4px;">' . esc_html__('Blokuoti IP', 'gratis-security') . '</button>';
                    echo '<button type="button" class="button button-small gs-req-quick-allow" data-ip="' . esc_attr($ip) . '">' . esc_html__('Leisti IP', 'gratis-security') . '</button>';
                }
                echo '</td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table>';

        echo '<div id="gs-requests-pager" class="gs-pager">';
        echo '<span id="gs-requests-pager-info">' . esc_html(sprintf('Puslapis 1 iš %d (viso %d)', $tot_pages, $tot_filt)) . '</span>';
        echo '<div class="gs-pager-btns">';
        echo '<button type="button" id="gs-req-prev" class="button button-small" disabled>' . esc_html__('Ankstesnis', 'gratis-security') . '</button>';
        echo '<button type="button" id="gs-req-next" class="button button-small"' . ($tot_pages <= 1 ? ' disabled' : '') . '>' . esc_html__('Kitas', 'gratis-security') . '</button>';
        echo '</div></div>';
        echo '</div>';

        // IP Management Card (Allowlist / Blocklist / Auto-Bans)
        echo '<div class="gs-card">';
        echo '<h2>' . esc_html__('IP valdymas (Blocklist / Allowlist / Auto-Banai)', 'gratis-security') . '</h2>';

        echo '<div class="gs-toolbar">';
        echo '<input type="text" id="gs-ip-input" placeholder="' . esc_attr__('IP arba CIDR (pvz. 192.0.2.10 arba 198.51.100.0/24)', 'gratis-security') . '" style="width:280px;">';
        echo '<select id="gs-ip-list">';
        echo '<option value="blocklist">' . esc_html__('Blokuoti (Blocklist)', 'gratis-security') . '</option>';
        echo '<option value="allowlist">' . esc_html__('Leisti (Allowlist)', 'gratis-security') . '</option>';
        echo '</select>';
        echo '<input type="text" id="gs-ip-note" placeholder="' . esc_attr__('Pastaba (nebūtina)', 'gratis-security') . '" style="width:220px;">';
        echo '<button type="button" id="gs-ip-add-btn" class="button button-primary">' . esc_html__('Pridėti IP taisyklę', 'gratis-security') . '</button>';
        echo '<span id="gs-ip-msg" class="gs-msg"></span>';
        echo '</div>';

        echo '<div class="gs-two-col">';

        // Active Auto-Bans
        echo '<div>';
        echo '<h3>' . esc_html__('Aktyvūs automatiniai banai', 'gratis-security') . '</h3>';
        echo '<table class="widefat striped">';
        echo '<thead><tr><th>IP</th><th>' . esc_html__('Galioja iki', 'gratis-security') . '</th><th>' . esc_html__('Priežastis', 'gratis-security') . '</th><th></th></tr></thead>';
        echo '<tbody id="gs-bans-body">';
        if (empty($active_bans)) {
            echo '<tr><td colspan="4" style="text-align:center; color:#646970;">' . esc_html__('Aktyvių banų nėra.', 'gratis-security') . '</td></tr>';
        } else {
            foreach ($active_bans as $ban) {
                $bip = (string) ($ban['ip'] ?? '');
                $until = gmdate('Y-m-d H:i', (int) ($ban['until'] ?? 0));
                echo '<tr>';
                echo '<td><code>' . esc_html($bip) . '</code></td>';
                echo '<td><span style="font-size:12px;">' . esc_html($until) . '</span></td>';
                echo '<td><span style="font-size:12px;">' . esc_html((string) ($ban['reason'] ?? '')) . '</span></td>';
                echo '<td><button type="button" class="button button-small gs-ip-unban-btn" data-ip="' . esc_attr($bip) . '">' . esc_html__('Atblokuoti', 'gratis-security') . '</button></td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table>';
        echo '</div>';

        // Blocklist & Allowlist
        echo '<div>';
        echo '<h3>' . esc_html__('Rankinis Blocklist / Allowlist', 'gratis-security') . '</h3>';
        echo '<table class="widefat striped">';
        echo '<thead><tr><th>' . esc_html__('Sąrašas', 'gratis-security') . '</th><th>IP / CIDR</th><th>' . esc_html__('Pastaba', 'gratis-security') . '</th><th></th></tr></thead>';
        echo '<tbody id="gs-ip-rules-body">';
        if (empty($blocklist) && empty($allowlist)) {
            echo '<tr><td colspan="4" style="text-align:center; color:#646970;">' . esc_html__('Rankinių IP taisyklių nėra.', 'gratis-security') . '</td></tr>';
        } else {
            foreach ($blocklist as $item) {
                $rip = (string) ($item['ip'] ?? '');
                echo '<tr>';
                echo '<td><span class="gs-badge gs-badge-danger">BLOCK</span></td>';
                echo '<td><code>' . esc_html($rip) . '</code></td>';
                echo '<td>' . esc_html((string) ($item['note'] ?? '')) . '</td>';
                echo '<td><button type="button" class="button button-small gs-ip-remove-btn" data-ip="' . esc_attr($rip) . '" data-list="blocklist">' . esc_html__('Pašalinti', 'gratis-security') . '</button></td>';
                echo '</tr>';
            }
            foreach ($allowlist as $item) {
                $rip = (string) ($item['ip'] ?? '');
                echo '<tr>';
                echo '<td><span class="gs-badge gs-badge-ok">ALLOW</span></td>';
                echo '<td><code>' . esc_html($rip) . '</code></td>';
                echo '<td>' . esc_html((string) ($item['note'] ?? '')) . '</td>';
                echo '<td><button type="button" class="button button-small gs-ip-remove-btn" data-ip="' . esc_attr($rip) . '" data-list="allowlist">' . esc_html__('Pašalinti', 'gratis-security') . '</button></td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table>';
        echo '</div>';

        echo '</div>';
        echo '</div>';

        self::render_js($nonce);
    }

    /**
     * Render safe DOM JS for Malicious Requests & IP rules.
     */
    private static function render_js(string $nonce): void {
        $ajax_url = admin_url('admin-ajax.php');
        ?>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var ajaxEndpoint = (typeof ajaxurl !== 'undefined') ? ajaxurl : '<?php echo esc_js($ajax_url); ?>';
            var nonce = '<?php echo esc_js($nonce); ?>';
            var perPage = <?php echo (int) self::PER_PAGE; ?>;
            var currentPage = 1;

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

            function badgeCls(val) {
                var v = String(val || '').toLowerCase();
                if (v === 'logged' || v === 'ok') return 'gs-badge gs-badge-ok';
                if (v === 'medium' || v === 'warn') return 'gs-badge gs-badge-warn';
                if (v === 'critical' || v === 'high' || v === 'blocked') return 'gs-badge gs-badge-danger';
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

            var searchEl = document.getElementById('gs-req-search');
            var catEl = document.getElementById('gs-req-category');
            var sevEl = document.getElementById('gs-req-severity');
            var actEl = document.getElementById('gs-req-action');
            var sinceEl = document.getElementById('gs-req-since');
            var spinner = document.getElementById('gs-req-spinner');
            var reqMsg = document.getElementById('gs-req-msg');
            var ipMsg = document.getElementById('gs-ip-msg');

            function renderRequests(data) {
                if (!data) return;
                var counts = data.counts || {};
                var k24 = document.getElementById('gs-req-kpi-24h');
                var kTot = document.getElementById('gs-req-kpi-total');
                var kAct = document.getElementById('gs-req-kpi-actions');
                var kBans = document.getElementById('gs-req-kpi-bans');
                if (k24) k24.textContent = String(counts.last_24h || 0);
                if (kTot) kTot.textContent = 'Iš viso žurnale: ' + String(counts.total || 0);
                if (kAct) kAct.textContent = String(counts.blocked || 0) + ' / ' + String(counts.logged || 0);
                if (kBans) kBans.textContent = String(counts.active_bans || 0);

                // Top IPs
                var topBox = document.getElementById('gs-req-top-ips');
                if (topBox && Array.isArray(data.top_ips)) {
                    clearNode(topBox);
                    if (!data.top_ips.length) {
                        var sp = el('span', 'Per pastarąsias 24 val. įtartinų IP neužfiksuota.');
                        sp.style.fontSize = '12px';
                        sp.style.color = '#646970';
                        topBox.appendChild(sp);
                    } else {
                        data.top_ips.forEach(function(tip) {
                            var pill = el('span', null, 'gs-pill');
                            pill.appendChild(el('code', String(tip.ip || '')));
                            pill.appendChild(el('strong', ' (' + String(tip.count || 0) + ')'));
                            if (tip.blocked) {
                                pill.appendChild(el('span', 'Blokuotas', 'gs-badge gs-badge-danger'));
                            } else {
                                var btn = el('button', 'Blokuoti IP', 'button button-small gs-req-quick-block');
                                btn.type = 'button';
                                btn.setAttribute('data-ip', String(tip.ip || ''));
                                pill.appendChild(btn);
                            }
                            topBox.appendChild(pill);
                        });
                    }
                }

                // Table
                var tbody = document.getElementById('gs-requests-body');
                if (tbody) {
                    clearNode(tbody);
                    var rows = Array.isArray(data.requests) ? data.requests : [];
                    if (!rows.length) {
                        var tr = document.createElement('tr');
                        var td = el('td', 'Įtartinų užklausų įrašų nėra.');
                        td.colSpan = 8;
                        td.style.textAlign = 'center';
                        td.style.color = '#646970';
                        td.style.padding = '16px';
                        tr.appendChild(td);
                        tbody.appendChild(tr);
                    } else {
                        rows.forEach(function(r) {
                            var tr = document.createElement('tr');
                            var ip = String(r.ip || '');
                            var sev = String(r.severity || 'medium');
                            var act = String(r.action || 'logged');

                            var tdT = document.createElement('td');
                            var tSpan = el('span', String(r.time || ''));
                            tSpan.style.fontSize = '12px';
                            tdT.appendChild(tSpan);

                            var tdIp = document.createElement('td');
                            tdIp.appendChild(el('code', ip));

                            var tdUri = document.createElement('td');
                            tdUri.appendChild(el('strong', String(r.method || 'GET') + ' '));
                            var uCode = el('code', String(r.uri || ''));
                            uCode.style.wordBreak = 'break-all';
                            tdUri.appendChild(uCode);

                            var tdCat = document.createElement('td');
                            tdCat.appendChild(el('code', String(r.category || '')));

                            var tdSev = document.createElement('td');
                            tdSev.appendChild(el('span', sev.toUpperCase(), badgeCls(sev)));

                            var tdAct = document.createElement('td');
                            tdAct.appendChild(el('span', act.toUpperCase(), badgeCls(act)));

                            var tdSnip = document.createElement('td');
                            tdSnip.appendChild(el('code', r.matched_snippet ? String(r.matched_snippet) : '—', 'gs-snippet'));

                            var tdQ = document.createElement('td');
                            tdQ.style.whiteSpace = 'nowrap';
                            if (ip) {
                                var bBtn = el('button', 'Blokuoti IP', 'button button-small gs-req-quick-block');
                                bBtn.type = 'button';
                                bBtn.style.marginRight = '4px';
                                bBtn.setAttribute('data-ip', ip);
                                var aBtn = el('button', 'Leisti IP', 'button button-small gs-req-quick-allow');
                                aBtn.type = 'button';
                                aBtn.setAttribute('data-ip', ip);
                                tdQ.appendChild(bBtn);
                                tdQ.appendChild(aBtn);
                            }

                            tr.appendChild(tdT);
                            tr.appendChild(tdIp);
                            tr.appendChild(tdUri);
                            tr.appendChild(tdCat);
                            tr.appendChild(tdSev);
                            tr.appendChild(tdAct);
                            tr.appendChild(tdSnip);
                            tr.appendChild(tdQ);
                            tbody.appendChild(tr);
                        });
                    }
                }

                currentPage = Number(data.page || 1);
                var totPages = Number(data.total_pages || 1);
                var totFilt = Number(data.total_filtered || 0);
                var infoEl = document.getElementById('gs-requests-pager-info');
                var prevBtn = document.getElementById('gs-req-prev');
                var nextBtn = document.getElementById('gs-req-next');
                if (infoEl) infoEl.textContent = 'Puslapis ' + currentPage + ' iš ' + totPages + ' (viso ' + totFilt + ')';
                if (prevBtn) prevBtn.disabled = currentPage <= 1;
                if (nextBtn) nextBtn.disabled = currentPage >= totPages;
            }

            function renderIpTables(rules, bans) {
                var rulesObj = rules || { blocklist: [], allowlist: [] };
                var blocklist = Array.isArray(rulesObj.blocklist) ? rulesObj.blocklist : [];
                var allowlist = Array.isArray(rulesObj.allowlist) ? rulesObj.allowlist : [];
                var bansList = Array.isArray(bans) ? bans : Object.keys(bans || {}).map(function(k) { return bans[k]; });

                var kRules = document.getElementById('gs-req-kpi-rules');
                var kBans = document.getElementById('gs-req-kpi-bans');
                if (kRules) kRules.textContent = blocklist.length + ' blokuoti / ' + allowlist.length + ' leisti';
                if (kBans) kBans.textContent = String(bansList.length);

                var bansBody = document.getElementById('gs-bans-body');
                if (bansBody) {
                    clearNode(bansBody);
                    if (!bansList.length) {
                        var tr = document.createElement('tr');
                        var td = el('td', 'Aktyvių banų nėra.');
                        td.colSpan = 4;
                        td.style.textAlign = 'center';
                        td.style.color = '#646970';
                        tr.appendChild(td);
                        bansBody.appendChild(tr);
                    } else {
                        bansList.forEach(function(b) {
                            var tr = document.createElement('tr');
                            var ip = String(b.ip || '');
                            var untilTxt = b.until ? new Date(Number(b.until) * 1000).toISOString().slice(0, 16).replace('T', ' ') : '';
                            var tdI = document.createElement('td');
                            tdI.appendChild(el('code', ip));
                            var tdU = document.createElement('td');
                            tdU.appendChild(el('span', untilTxt));
                            var tdR = document.createElement('td');
                            tdR.appendChild(el('span', String(b.reason || '')));
                            var tdB = document.createElement('td');
                            var uBtn = el('button', 'Atblokuoti', 'button button-small gs-ip-unban-btn');
                            uBtn.type = 'button';
                            uBtn.setAttribute('data-ip', ip);
                            tdB.appendChild(uBtn);
                            tr.appendChild(tdI);
                            tr.appendChild(tdU);
                            tr.appendChild(tdR);
                            tr.appendChild(tdB);
                            bansBody.appendChild(tr);
                        });
                    }
                }

                var rulesBody = document.getElementById('gs-ip-rules-body');
                if (rulesBody) {
                    clearNode(rulesBody);
                    if (!blocklist.length && !allowlist.length) {
                        var trE = document.createElement('tr');
                        var tdE = el('td', 'Rankinių IP taisyklių nėra.');
                        tdE.colSpan = 4;
                        tdE.style.textAlign = 'center';
                        tdE.style.color = '#646970';
                        trE.appendChild(tdE);
                        rulesBody.appendChild(trE);
                    } else {
                        blocklist.forEach(function(item) {
                            var tr = document.createElement('tr');
                            var ip = String(item.ip || '');
                            var tdL = document.createElement('td');
                            tdL.appendChild(el('span', 'BLOCK', 'gs-badge gs-badge-danger'));
                            var tdI = document.createElement('td');
                            tdI.appendChild(el('code', ip));
                            var tdN = el('td', String(item.note || ''));
                            var tdB = document.createElement('td');
                            var rm = el('button', 'Pašalinti', 'button button-small gs-ip-remove-btn');
                            rm.type = 'button';
                            rm.setAttribute('data-ip', ip);
                            rm.setAttribute('data-list', 'blocklist');
                            tdB.appendChild(rm);
                            tr.appendChild(tdL);
                            tr.appendChild(tdI);
                            tr.appendChild(tdN);
                            tr.appendChild(tdB);
                            rulesBody.appendChild(tr);
                        });
                        allowlist.forEach(function(item) {
                            var tr = document.createElement('tr');
                            var ip = String(item.ip || '');
                            var tdL = document.createElement('td');
                            tdL.appendChild(el('span', 'ALLOW', 'gs-badge gs-badge-ok'));
                            var tdI = document.createElement('td');
                            tdI.appendChild(el('code', ip));
                            var tdN = el('td', String(item.note || ''));
                            var tdB = document.createElement('td');
                            var rm = el('button', 'Pašalinti', 'button button-small gs-ip-remove-btn');
                            rm.type = 'button';
                            rm.setAttribute('data-ip', ip);
                            rm.setAttribute('data-list', 'allowlist');
                            tdB.appendChild(rm);
                            tr.appendChild(tdL);
                            tr.appendChild(tdI);
                            tr.appendChild(tdN);
                            tr.appendChild(tdB);
                            rulesBody.appendChild(tr);
                        });
                    }
                }
            }

            function fetchRequests(page) {
                if (spinner) spinner.classList.add('is-active');
                postAjax('gratis_requests_query', {
                    search: searchEl ? searchEl.value.trim() : '',
                    category: catEl ? catEl.value : 'all',
                    severity: sevEl ? sevEl.value : 'all',
                    action_filter: actEl ? actEl.value : 'all',
                    since: sinceEl ? sinceEl.value : 'all',
                    page: String(page || currentPage),
                    per_page: String(perPage)
                }).then(function(res) {
                    if (res && res.success && res.data) {
                        renderRequests(res.data);
                    }
                }).finally(function() {
                    if (spinner) spinner.classList.remove('is-active');
                });
            }

            function doIpAction(subaction, payload) {
                payload.subaction = subaction;
                postAjax('gratis_requests_ip', payload).then(function(res) {
                    if (!res || !res.success || !res.data) {
                        var errTxt = (res && res.data && res.data.message) ? res.data.message : 'Veiksmas nepavyko.';
                        if (ipMsg) { ipMsg.style.color = '#d63638'; ipMsg.textContent = errTxt; }
                        return;
                    }
                    if (res.data.rules || res.data.bans) {
                        renderIpTables(res.data.rules, res.data.bans);
                    }
                    if (ipMsg && res.data.message) {
                        ipMsg.style.color = '#00a32a';
                        ipMsg.textContent = res.data.message;
                    }
                    if (reqMsg && subaction === 'clear_logs') {
                        reqMsg.style.color = '#00a32a';
                        reqMsg.textContent = 'Žurnalas išvalytas.';
                    }
                    fetchRequests(subaction === 'clear_logs' ? 1 : currentPage);
                });
            }

            var timer = null;
            if (searchEl) searchEl.addEventListener('input', function() { clearTimeout(timer); timer = setTimeout(function() { fetchRequests(1); }, 250); });
            if (catEl) catEl.addEventListener('change', function() { fetchRequests(1); });
            if (sevEl) sevEl.addEventListener('change', function() { fetchRequests(1); });
            if (actEl) actEl.addEventListener('change', function() { fetchRequests(1); });
            if (sinceEl) sinceEl.addEventListener('change', function() { fetchRequests(1); });

            var refreshBtn = document.getElementById('gs-req-refresh-btn');
            var clearBtn = document.getElementById('gs-req-clear-btn');
            var prevBtn = document.getElementById('gs-req-prev');
            var nextBtn = document.getElementById('gs-req-next');
            if (refreshBtn) refreshBtn.addEventListener('click', function() { fetchRequests(currentPage); });
            if (clearBtn) clearBtn.addEventListener('click', function() {
                if (!confirm('Išvalyti visą užklausų žurnalą?')) return;
                doIpAction('clear_logs', {});
            });
            if (prevBtn) prevBtn.addEventListener('click', function() { if (currentPage > 1) fetchRequests(currentPage - 1); });
            if (nextBtn) nextBtn.addEventListener('click', function() { fetchRequests(currentPage + 1); });

            var addIpBtn = document.getElementById('gs-ip-add-btn');
            if (addIpBtn) {
                addIpBtn.addEventListener('click', function() {
                    var ipInput = document.getElementById('gs-ip-input');
                    var listSel = document.getElementById('gs-ip-list');
                    var noteInput = document.getElementById('gs-ip-note');
                    var ipVal = ipInput ? ipInput.value.trim() : '';
                    var listVal = listSel ? listSel.value : 'blocklist';
                    if (!ipVal) return;
                    doIpAction(listVal === 'allowlist' ? 'allow' : 'block', {
                        ip: ipVal,
                        note: noteInput ? noteInput.value.trim() : ''
                    });
                    if (ipInput) ipInput.value = '';
                    if (noteInput) noteInput.value = '';
                });
            }

            document.addEventListener('click', function(e) {
                var t = e.target;
                if (!t || !t.closest) return;
                var qb = t.closest('.gs-req-quick-block');
                if (qb) {
                    doIpAction('block', { ip: qb.getAttribute('data-ip') || '', note: 'Admin quick block' });
                    return;
                }
                var qa = t.closest('.gs-req-quick-allow');
                if (qa) {
                    doIpAction('allow', { ip: qa.getAttribute('data-ip') || '', note: 'Admin quick allow' });
                    return;
                }
                var ub = t.closest('.gs-ip-unban-btn');
                if (ub) {
                    doIpAction('unban', { ip: ub.getAttribute('data-ip') || '' });
                    return;
                }
                var rm = t.closest('.gs-ip-remove-btn');
                if (rm) {
                    doIpAction('remove_rule', {
                        ip: rm.getAttribute('data-ip') || '',
                        list: rm.getAttribute('data-list') || 'blocklist'
                    });
                }
            });
        });
        </script>
        <?php
    }
}
