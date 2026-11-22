<?php declare(strict_types=1);

PHP_SAPI === 'cli' || exit(1);

$tmp_root = sys_get_temp_dir() . '/gratis_sec_test_' . bin2hex(random_bytes(4));
$tmp_web  = $tmp_root . '/web';
$tmp_wp   = $tmp_web . '/wp';
$tmp_uploads = $tmp_web . '/app/uploads';
$tmp_storage = $tmp_uploads . '/gratis-security';

@mkdir($tmp_wp . '/wp-includes', 0755, true);
@mkdir($tmp_uploads, 0755, true);
@mkdir($tmp_web . '/app/cache', 0755, true);
@mkdir($tmp_web . '/app/plugins/demo-plugin', 0755, true);
@mkdir($tmp_storage, 0755, true);

define('ABSPATH', $tmp_wp . '/');
define('WP_CONTENT_DIR', $tmp_web . '/app');

if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir(): array {
        return ['basedir' => WP_CONTENT_DIR . '/uploads'];
    }
}
if (!function_exists('wp_mkdir_p')) {
    function wp_mkdir_p(string $target): bool {
        return is_dir($target) || @mkdir($target, 0755, true);
    }
}
if (!function_exists('wp_next_scheduled')) {
    function wp_next_scheduled(string $hook): bool {
        return false;
    }
}
if (!function_exists('__')) {
    function __(string $text, string $domain = 'default'): string {
        return $text;
    }
}

require_once dirname(__DIR__) . '/autoload.php';

use Gratis\Security\EventMonitor;
use Gratis\Security\FileIntegrity;
use Gratis\Security\ServerInspector;

function rm_rf(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }
    $items = scandir($dir);
    if (!is_array($items)) {
        return;
    }
    foreach ($items as $item) {
        if ('.' === $item || '..' === $item) {
            continue;
        }
        $path = $dir . '/' . $item;
        if (is_dir($path) && !is_link($path)) {
            rm_rf($path);
        } else {
            @unlink($path);
        }
    }
    @rmdir($dir);
}

try {
    // 1. ServerInspector::detect_os()
    $rhel = ServerInspector::detect_os("ID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 9.4 (Plow)\"\n", 'Linux', 'x86_64');
    assert($rhel['id'] === 'rhel');
    assert($rhel['family'] === 'rhel');
    assert($rhel['version_id'] === '9.4');
    assert($rhel['audit_arch'] === 'b64');

    $ubuntu = ServerInspector::detect_os("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n", 'Linux', 'aarch64');
    assert($ubuntu['id'] === 'ubuntu');
    assert($ubuntu['family'] === 'debian');
    assert($ubuntu['audit_arch'] === 'b64');

    $alpine = ServerInspector::detect_os("ID=alpine\nVERSION_ID=3.20.1\nPRETTY_NAME=\"Alpine Linux v3.20\"\n", 'Linux', 'armv7l');
    assert($alpine['id'] === 'alpine');
    assert($alpine['family'] === 'alpine');
    assert($alpine['audit_arch'] === 'b32');

    $macos = ServerInspector::detect_os('', 'Darwin', 'arm64');
    assert($macos['family'] === 'macos');
    assert($macos['init_system'] === 'launchd');
    assert($macos['audit_arch'] === 'b64');

    // 2. ServerInspector::analyze_systemd_unit()
    $expected_web = '/var/www/12fa/deploy/current/web';
    $valid_unit = "[Unit]\nDescription=Gratis\n[Service]\nUser=www-data\nGroup=www-data\n"
        . "ExecStart=/usr/bin/inotifywait -m -r -e close_write \\\n"
        . "    --timefmt '%%Y-%%m-%%dT%%H:%%M:%%S%%z' \\\n"
        . "    --format '{\"time\":\"%%T\",\"event\":\"%%e\",\"file\":\"%%w%%f\"}' \\\n"
        . "    --exclude '/(uploads|cache|\\\\.git)/' \\\n"
        . "    '/var/www/12fa/deploy/current/web'\n"
        . "StandardOutput=append:/var/www/12fa/shared/fim-events.jsonl\n";

    $u_ok = ServerInspector::analyze_systemd_unit($valid_unit, $expected_web);
    assert($u_ok['valid'] === true);
    assert($u_ok['user'] === 'www-data');
    assert($u_ok['group'] === 'www-data');
    assert($u_ok['log_path'] === '/var/www/12fa/shared/fim-events.jsonl');
    assert(empty($u_ok['issues']));

    $bad_pct = str_replace('%%T', '%T', $valid_unit);
    $u_pct = ServerInspector::analyze_systemd_unit($bad_pct, $expected_web);
    assert($u_pct['valid'] === false);
    assert(count($u_pct['issues']) >= 1);

    $no_timefmt = str_replace("--timefmt '%%Y-%%m-%%dT%%H:%%M:%%S%%z' \\\n", '', $valid_unit);
    $u_tf = ServerInspector::analyze_systemd_unit($no_timefmt, $expected_web);
    assert($u_tf['valid'] === false);

    $single_bs = str_replace('\\\\.git', '\\.git', $valid_unit);
    $u_bs = ServerInspector::analyze_systemd_unit($single_bs, $expected_web);
    assert($u_bs['valid'] === false);

    $stale_path = str_replace($expected_web, '/var/www/12fa/deploy/releases/20250101/web', $valid_unit);
    $u_stale = ServerInspector::analyze_systemd_unit($stale_path, $expected_web);
    assert($u_stale['valid'] === false);

    // 3. ServerInspector::analyze_audit_rules()
    $modern_rules = "-a always,exit -F arch=b64 -F dir=/var/www/12fa/deploy/current/web -F perm=wa -F key=gratis_fim\n";
    $a_mod = ServerInspector::analyze_audit_rules($modern_rules, $expected_web);
    assert($a_mod['has_rule'] === true);
    assert($a_mod['is_modern_syscall'] === true);
    assert($a_mod['is_legacy_watch'] === false);
    assert($a_mod['matches_path'] === true);
    assert(empty($a_mod['issues']));

    $legacy_rules = "-w /var/www/12fa/deploy/current/web -p wa -k gratis_fim\n";
    $a_leg = ServerInspector::analyze_audit_rules($legacy_rules, $expected_web);
    assert($a_leg['has_rule'] === true);
    assert($a_leg['is_legacy_watch'] === true);
    assert(!empty($a_leg['issues']));

    $a_empty = ServerInspector::analyze_audit_rules("", $expected_web);
    assert($a_empty['has_rule'] === false);

    // 4. ServerInspector::build_recommendations()
    $base_inspection = [
        'runtime' => ['user' => 'nginx', 'group' => 'nginx', 'uid' => 998, 'gid' => 996, 'is_root' => false],
        'os'      => array_merge($rhel, ['init_system' => 'systemd']),
        'tools'   => [
            'auditctl'    => ['available' => false, 'path' => ''],
            'inotifywait' => ['available' => false, 'path' => ''],
            'wp'          => ['available' => true, 'path' => '/usr/local/bin/wp'],
            'pkg_manager' => ['name' => 'dnf', 'path' => '/usr/bin/dnf'],
        ],
        'paths'   => [
            'web_dir'        => '/var/www/site/web',
            'wp_path'        => '/var/www/site/web/wp',
            'storage_dir'    => '/var/www/site/web/app/uploads/gratis-security',
            'symlink_deploy' => ['is_symlink' => true, 'symlink_path' => '/var/www/site/current', 'resolved_path' => '/var/www/site/releases/1'],
            'event_log'      => ['readable' => false],
        ],
        'services' => [
            'auditd'     => ['status' => 'missing', 'summary' => 'missing', 'kernel_rules_analysis' => null, 'rules_file_analysis' => null],
            'gratis_fim' => ['status' => 'missing', 'summary' => 'missing'],
        ],
        'cron' => ['system_cron_found' => false, 'wp_cron_trail' => false, 'summary' => 'none'],
    ];

    $rec_php = ServerInspector::build_recommendations($base_inspection, 'php');
    assert($rec_php['tier'] === 'kernel_and_realtime');
    assert(str_contains($rec_php['install'], 'dnf install -y'));
    assert(str_contains($rec_php['service'], 'User=nginx'));
    assert(str_contains($rec_php['service'], 'Group=nginx'));
    assert(str_contains($rec_php['service'], 'ProtectSystem=strict'));
    assert(str_contains($rec_php['service'], 'ReadWritePaths='));
    assert(str_contains($rec_php['service'], 'ProtectHome=yes'));
    assert(str_contains($rec_php['service'], '%%T'));
    assert(str_contains($rec_php['service'], '--timefmt'));
    assert(str_contains($rec_php['service'], '\\\\.git'));
    assert(str_contains($rec_php['inotify'], 'touch '));
    assert(str_contains($rec_php['inotify'], 'chown '));
    assert(!str_contains($rec_php['inotify'], 'install -o'));
    assert(str_contains($rec_php['cron'], 'sudo tee /etc/cron.d/gratis-security'));
    assert(str_contains($rec_php['cron'], 'sudo chmod 644 /etc/cron.d/gratis-security'));

    $rec_root = ServerInspector::build_recommendations($base_inspection, 'root');
    assert(str_contains($rec_root['service'], 'User=root'));
    assert(str_contains($rec_root['service'], '/var/log/gratis-fim.jsonl'));

    // ProtectHome=yes must be omitted when path starts with /home/
    $home_inspection = $base_inspection;
    $home_inspection['os'] = array_merge($ubuntu, ['init_system' => 'systemd']);
    $home_inspection['tools']['pkg_manager'] = ['name' => 'apt-get', 'path' => '/usr/bin/apt-get'];
    $home_inspection['paths']['web_dir'] = '/home/deploy/site/web';
    $rec_home = ServerInspector::build_recommendations($home_inspection, 'php');
    assert(!str_contains($rec_home['service'], 'ProtectHome=yes'));
    assert(str_contains($rec_home['install'], 'apt-get install -y'));

    // 5. EventMonitor::trail(), query_events(), query_detections(), update_detection_status(), clear_detections()
    $log_file = $tmp_root . '/test-fim.jsonl';

    // Create actual files on disk for content/hash inspection
    $jpg_file = $tmp_uploads . '/photo.jpg';
    file_put_contents($jpg_file, 'jpegbytes');

    $shell_file = $tmp_uploads . '/shell.php';
    file_put_contents($shell_file, '<?php eval(base64_decode($_POST["x"]));');

    $core_file = $tmp_wp . '/wp-includes/version.php';
    file_put_contents($core_file, '<?php $wp_version = "6.7";');

    $cache_file = $tmp_web . '/app/cache/page.html';
    file_put_contents($cache_file, '<html>cached</html>');

    $plugin_match = $tmp_web . '/app/plugins/demo-plugin/ok.php';
    file_put_contents($plugin_match, "<?php // clean\n");
    $plugin_drift = $tmp_web . '/app/plugins/demo-plugin/changed.php';
    file_put_contents($plugin_drift, "<?php // tampered\n");

    $manifest_content = hash_file('sha256', $plugin_match) . "  web/app/plugins/demo-plugin/ok.php\n"
        . str_repeat('0', 64) . "  web/app/plugins/demo-plugin/changed.php\n";
    file_put_contents($tmp_root . '/SOURCE-MANIFEST.sha256', $manifest_content);

    $now = time();
    $ts1 = gmdate('c', $now - 20);
    $events_jsonl = implode("\n", [
        json_encode(['time' => $ts1, 'event' => 'CLOSE_WRITE,CLOSE', 'file' => $jpg_file]),
        json_encode(['time' => $ts1, 'event' => 'CLOSE_WRITE,CLOSE', 'file' => $shell_file]),
        json_encode(['time' => $ts1, 'event' => 'MODIFY', 'file' => $core_file]),
        json_encode(['time' => $ts1, 'event' => 'CREATE', 'file' => $cache_file]),
        json_encode(['time' => $ts1, 'event' => 'CLOSE_WRITE,CLOSE', 'file' => $plugin_match]),
        json_encode(['time' => $ts1, 'event' => 'CLOSE_WRITE,CLOSE', 'file' => $plugin_drift]),
    ]) . "\n";
    file_put_contents($log_file, $events_jsonl);

    // Direct evaluate_event check: manifest-verified file MUST return null (no code_modified_runtime fallthrough)
    $manifest_map = [
        'web/app/plugins/demo-plugin/ok.php'      => hash_file('sha256', $plugin_match),
        'web/app/plugins/demo-plugin/changed.php' => str_repeat('0', 64),
    ];
    $ok_eval = EventMonitor::evaluate_event([
        'time'      => $ts1,
        'event'     => 'CLOSE_WRITE,CLOSE',
        'raw_path'  => $plugin_match,
        'path'      => 'web/app/plugins/demo-plugin/ok.php',
        'component' => 'plugins',
    ], $tmp_root, $manifest_map);
    assert($ok_eval === null);

    // Ephemeral untracked file DELETE outside manifest must return null
    $del_eval = EventMonitor::evaluate_event([
        'time'      => $ts1,
        'event'     => 'DELETE',
        'raw_path'  => $tmp_web . '/app/plugins/demo-plugin/ephemeral.php',
        'path'      => 'web/app/plugins/demo-plugin/ephemeral.php',
        'component' => 'plugins',
    ], $tmp_root, $manifest_map);
    assert($del_eval === null);

    // Expanded ignored paths
    assert(EventMonitor::is_ignored_path('web/app/uploads/elementor/css/post-12.css') === true);
    assert(EventMonitor::is_ignored_path('web/app/cache/wp-rocket/index.html') === true);
    assert(EventMonitor::is_ignored_path('web/app/plugins/foo/app.min.js.map') === true);
    assert(EventMonitor::is_ignored_path('web/app/logs/debug.log') === true);

    // Multisite storage log discovery fallback
    $ms_sources = EventMonitor::discover_log_sources($tmp_uploads . '/sites/3/gratis-security');
    $ms_paths   = array_column($ms_sources, 'path');
    assert(in_array($tmp_uploads . '/gratis-security/fim-events.jsonl', $ms_paths, true));

    $trail1 = EventMonitor::trail([$log_file], $tmp_storage, $tmp_root);
    assert($trail1['sources_checked'] === 1);
    assert($trail1['lines_read'] === 6);
    assert($trail1['events_parsed'] === 6);
    // Expected detections: shell.php (critical), version.php (high), changed.php (manifest_drift, high) -> 3
    assert($trail1['new_detections'] === 3);

    $rules_triggered = array_column($trail1['detections'], 'rule');
    assert(in_array('executable_in_uploads', $rules_triggered, true));
    assert(in_array('core_or_config_modified', $rules_triggered, true));
    assert(in_array('manifest_drift', $rules_triggered, true));

    // Second trail with no new lines
    $trail2 = EventMonitor::trail([$log_file], $tmp_storage, $tmp_root);
    assert($trail2['lines_read'] === 0);
    assert($trail2['new_detections'] === 0);

    // Append duplicate event within 60s -> deduplicated
    $ts_dup = gmdate('c', $now - 10);
    file_put_contents($log_file, json_encode(['time' => $ts_dup, 'event' => 'CLOSE_WRITE,CLOSE', 'file' => $shell_file]) . "\n", FILE_APPEND);
    $trail3 = EventMonitor::trail([$log_file], $tmp_storage, $tmp_root);
    assert($trail3['lines_read'] === 1);
    assert($trail3['new_detections'] === 0);

    // Truncate/rotate log and write a new critical event
    $shell_file2 = $tmp_uploads . '/backdoor2.php';
    file_put_contents($shell_file2, '<?php system($_GET["c"]);');
    file_put_contents($log_file, json_encode(['time' => gmdate('c', $now), 'event' => 'CREATE', 'file' => $shell_file2]) . "\n");
    $trail4 = EventMonitor::trail([$log_file], $tmp_storage, $tmp_root);
    assert($trail4['lines_read'] === 1);
    assert($trail4['new_detections'] === 1);
    assert($trail4['detections'][0]['rule'] === 'executable_in_uploads');

    // query_events filters
    $q_all = EventMonitor::query_events([], [$log_file], $tmp_storage, $tmp_root);
    assert($q_all['total_matched'] === 1);

    $q_all_explicit = EventMonitor::query_events(['event' => 'all', 'component' => 'all', 'source' => 'all'], [$log_file], $tmp_storage, $tmp_root);
    assert($q_all_explicit['total_matched'] === 1);

    $q_susp = EventMonitor::query_events(['search' => 'backdoor2', 'event' => 'CREATE', 'component' => 'uploads', 'only_suspicious' => true], [$log_file], $tmp_storage, $tmp_root);
    assert($q_susp['total_matched'] === 1);
    assert(!empty($q_susp['events'][0]['detection_preview']));

    // query_detections, pagination, update_detection_status, bulk_update_status, purge_verified_detections, clear_detections
    $dets_all = EventMonitor::query_detections([], $tmp_storage);
    assert($dets_all['counts']['total'] === 4);
    assert($dets_all['counts']['open'] === 4);
    assert($dets_all['counts']['critical'] === 2);

    $dets_page1 = EventMonitor::query_detections(['page' => 1, 'per_page' => 2], $tmp_storage);
    assert(count($dets_page1['detections']) === 2);
    assert($dets_page1['total_filtered'] === 4);
    assert($dets_page1['page'] === 1);
    assert($dets_page1['per_page'] === 2);
    assert($dets_page1['total_pages'] === 2);

    $dets_page2 = EventMonitor::query_detections(['page' => 2, 'per_page' => 2], $tmp_storage);
    assert(count($dets_page2['detections']) === 2);
    assert($dets_page2['detections'][0]['id'] !== $dets_page1['detections'][0]['id']);

    $dets_status_all = EventMonitor::query_detections(['status' => 'all', 'severity' => 'all', 'component' => 'all'], $tmp_storage);
    assert(count($dets_status_all['detections']) === 4);

    $dets_crit = EventMonitor::query_detections(['severity' => 'critical'], $tmp_storage);
    assert(count($dets_crit['detections']) === 2);

    $target_id = $dets_crit['detections'][0]['id'];
    assert(EventMonitor::update_detection_status($target_id, 'acknowledged', $tmp_storage) === true);
    $after_ack = EventMonitor::query_detections(['status' => 'acknowledged'], $tmp_storage);
    assert(count($after_ack['detections']) === 1);

    $after_ack_all = EventMonitor::query_detections(['status' => 'all'], $tmp_storage);
    assert(count($after_ack_all['detections']) === 4);

    assert(EventMonitor::update_detection_status($target_id, 'resolved', $tmp_storage) === true);
    $removed = EventMonitor::clear_detections('resolved', $tmp_storage);
    assert($removed === 1);

    $after_clear = EventMonitor::query_detections([], $tmp_storage);
    assert($after_clear['counts']['total'] === 3);

    // bulk_update_status
    $bulk_updated = EventMonitor::bulk_update_status(['severity' => 'high', 'status' => 'open'], 'acknowledged', $tmp_storage);
    assert($bulk_updated === 2);
    $after_bulk = EventMonitor::query_detections(['status' => 'acknowledged'], $tmp_storage);
    assert(count($after_bulk['detections']) === 2);

    // purge_verified_detections removes manifest-verified, ignored-path, and deleted-untracked false positives
    $det_file = $tmp_storage . '/' . EventMonitor::DETECTIONS_FILE;
    $fp_rows  = [
        json_encode([
            'id'        => 'det_fp_manifest',
            'rule'      => 'code_modified_runtime',
            'severity'  => 'medium',
            'path'      => 'web/app/plugins/demo-plugin/ok.php',
            'raw_path'  => $plugin_match,
            'event'     => 'CLOSE_WRITE,CLOSE',
            'component' => 'plugins',
            'status'    => 'open',
        ]),
        json_encode([
            'id'        => 'det_fp_ignored',
            'rule'      => 'code_modified_runtime',
            'severity'  => 'medium',
            'path'      => 'web/app/uploads/elementor/css/post-99.css',
            'raw_path'  => '',
            'event'     => 'CLOSE_WRITE,CLOSE',
            'component' => 'uploads',
            'status'    => 'open',
        ]),
        json_encode([
            'id'        => 'det_fp_deleted',
            'rule'      => 'code_modified_runtime',
            'severity'  => 'medium',
            'path'      => 'web/app/plugins/demo-plugin/temp-gone.php',
            'raw_path'  => '',
            'event'     => 'DELETE',
            'component' => 'plugins',
            'status'    => 'open',
        ]),
    ];
    file_put_contents($det_file, implode("\n", $fp_rows) . "\n", FILE_APPEND);
    $purge_res = EventMonitor::purge_verified_detections($tmp_root, $tmp_storage);
    assert($purge_res['removed'] === 3);
    assert($purge_res['remaining'] === 3);

    // Verify ServerInspector::inspect() includes 7 checks including wp_cli
    $insp = ServerInspector::inspect('php');
    assert(count($insp['checks']) === 7);
    $check_ids = array_column($insp['checks'], 'id');
    assert(in_array('wp_cli', $check_ids, true));

    // Verify backwards compatibility of FileIntegrity::detect_server_capabilities & get_server_instructions
    $caps = FileIntegrity::detect_server_capabilities();
    foreach (['mode', 'os', 'auditctl', 'inotifywait', 'project_root', 'event_log', 'has_manifests'] as $k) {
        assert(array_key_exists($k, $caps));
    }
    $instr = FileIntegrity::get_server_instructions();
    foreach (['auditd', 'inotify', 'aide', 'wpcli', 'service'] as $k) {
        assert(array_key_exists($k, $instr));
    }

    echo "All ServerInspector & EventMonitor assertions passed!\n";
} finally {
    rm_rf($tmp_root);
}
