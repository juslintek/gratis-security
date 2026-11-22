<?php declare(strict_types=1);

PHP_SAPI === 'cli' || exit(1);

$tmp_root    = sys_get_temp_dir() . '/gratis_sec_eng_' . bin2hex(random_bytes(4));
$tmp_web     = $tmp_root . '/web';
$tmp_wp      = $tmp_web . '/wp';
$tmp_uploads = $tmp_web . '/app/uploads';
$tmp_storage = $tmp_uploads . '/gratis-security';

@mkdir($tmp_wp . '/wp-includes', 0755, true);
@mkdir($tmp_uploads, 0755, true);
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
if (!function_exists('get_option')) {
    function get_option(string $option, mixed $default = false): mixed {
        return $GLOBALS['gratis_test_options'][$option] ?? $default;
    }
}
if (!function_exists('__')) {
    function __(string $text, string $domain = 'default'): string {
        return $text;
    }
}

$GLOBALS['gratis_test_options'] = [
    'gratis_security_settings' => [
        'waf_enabled'       => 1,
        'waf_mode'          => 'block',
        'block_xmlrpc'      => 1,
        'headers_enabled'   => 1,
        'login_protection'  => 1,
        'integrity_enabled' => 1,
        'twofa_enabled'     => 0,
    ],
];

require_once dirname(__DIR__) . '/autoload.php';

use Gratis\Security\MalwareScanner;
use Gratis\Security\SecurityAudit;
use Gratis\Security\SignatureFeed;

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
    // 1. SignatureFeed::builtin_bundle()
    $bundle = SignatureFeed::builtin_bundle();
    assert(!empty($bundle['version']));
    assert(count($bundle['malware_rules']) >= 35);
    assert(count($bundle['request_rules']) >= 25);
    assert(!empty($bundle['bad_hashes']));

    foreach ($bundle['malware_rules'] as $rule) {
        assert(!empty($rule['id']));
        assert(!empty($rule['category']));
        assert(in_array($rule['severity'], ['critical', 'high', 'medium'], true));
        assert(!empty($rule['extensions']) && is_array($rule['extensions']));
        assert(false !== @preg_match($rule['pattern'], ''));
        assert(SignatureFeed::is_safe_regex($rule['pattern']) === true);
    }

    foreach ($bundle['request_rules'] as $rule) {
        assert(!empty($rule['id']));
        assert(!empty($rule['category']));
        assert(in_array($rule['severity'], ['critical', 'high', 'medium', 'low'], true));
        assert(in_array($rule['target'], ['uri', 'query', 'body', 'input', 'ua', 'all'], true));
        assert(false !== @preg_match($rule['pattern'], ''));
        assert(SignatureFeed::is_safe_regex($rule['pattern']) === true);
    }

    // 2. SignatureFeed::validate_remote_bundle()
    $valid_hash   = str_repeat('a', 64);
    $mixed_bundle = SignatureFeed::validate_remote_bundle([
        'version'       => '2026.11.24',
        'malware_rules' => [
            [
                'id'         => 'custom_ok',
                'category'   => 'backdoor',
                'severity'   => 'high',
                'label'      => 'Custom test rule',
                'pattern'    => '/evil_custom_fn\s*\(/i',
                'extensions' => ['php'],
            ],
            [
                'id'         => 'custom_broken_regex',
                'category'   => 'backdoor',
                'severity'   => 'high',
                'label'      => 'Broken regex',
                'pattern'    => '/[unclosed',
                'extensions' => ['php'],
            ],
            [
                'id'         => 'custom_redos',
                'category'   => 'backdoor',
                'severity'   => 'high',
                'label'      => 'Nested quantifier ReDoS',
                'pattern'    => '/(a+)+$/',
                'extensions' => ['php'],
            ],
        ],
        'bad_hashes'    => [
            $valid_hash => 'Known dropper',
            'not-a-sha' => 'Invalid hash',
        ],
        'blocked_ips'   => [
            '203.0.113.5',
            '198.51.100.0/24',
            '2001:db8::/32',
            '999.999.999.999',
            '10.0.0.1/99',
        ],
    ]);

    assert($mixed_bundle['valid'] === true);
    assert(count($mixed_bundle['bundle']['malware_rules']) === 1);
    assert($mixed_bundle['bundle']['malware_rules'][0]['id'] === 'custom_ok');
    assert(count($mixed_bundle['bundle']['bad_hashes']) === 1);
    assert(isset($mixed_bundle['bundle']['bad_hashes'][$valid_hash]));
    assert(count($mixed_bundle['bundle']['blocked_ips']) === 3);
    assert($mixed_bundle['rejected'] === 5);
    assert(count($mixed_bundle['errors']) === 5);

    $bad_only = SignatureFeed::validate_remote_bundle([
        'malware_rules' => [
            ['id' => 'broken', 'label' => 'Broken', 'severity' => 'high', 'pattern' => '/(unclosed'],
        ],
    ]);
    assert($bad_only['valid'] === false);
    assert($bad_only['rejected'] === 1);

    // 3. SignatureFeed::update() & get_status()
    $update_res = SignatureFeed::update(['sync_wp_checksums' => false], $tmp_storage);
    assert(file_exists($tmp_storage . '/' . SignatureFeed::SIGNATURES_FILE));
    assert(!empty($update_res['last_updated']));
    assert($update_res['counts']['malware_rules'] >= 35);
    assert($update_res['counts']['request_rules'] >= 25);

    $status = SignatureFeed::get_status($tmp_storage);
    assert($status['last_updated'] === $update_res['last_updated']);
    assert($status['counts']['malware_rules'] === $update_res['counts']['malware_rules']);

    // 4. MalwareScanner::scan()
    $benign_file = $tmp_web . '/app/plugins/demo-plugin/clean.php';
    file_put_contents($benign_file, "<?php\nfunction demo_hello(): string { return 'hello'; }\n");

    $webshell_file = $tmp_web . '/app/plugins/demo-plugin/webshell.php';
    $webshell_body = "<?php\n// hidden\n@eval(base64_decode(\$_POST['x']));\n";
    file_put_contents($webshell_file, $webshell_body);

    $gif_shell_file = $tmp_web . '/app/plugins/demo-plugin/logo.php';
    file_put_contents($gif_shell_file, "GIF89a<?php system(\$_GET['c']); ?>\n");

    $uploads_evil = $tmp_uploads . '/evil.php';
    file_put_contents($uploads_evil, "<?php echo 'rogue';\n");

    // EICAR test string matches built-in bad SHA-256 hash in a scanned .js file.
    $eicar_file = $tmp_web . '/app/plugins/demo-plugin/eicar.js';
    file_put_contents($eicar_file, 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');

    // Verified manifest file (clean when deep=false, also has a pattern to verify deep=true scans it).
    $manifest_file = $tmp_web . '/app/plugins/demo-plugin/manifest-verified.php';
    file_put_contents($manifest_file, "<?php\n@eval(str_rot13('nop'));\n");
    $manifest_content = hash_file('sha256', $manifest_file) . "  web/app/plugins/demo-plugin/manifest-verified.php\n";
    file_put_contents($tmp_root . '/SOURCE-MANIFEST.sha256', $manifest_content);

    // Self-exclusion check against the gratis-security plugin directory itself.
    $self_scan = MalwareScanner::scan(dirname(__DIR__), [
        'storage_dir' => $tmp_storage,
        'save_report' => false,
    ]);
    assert($self_scan['scanned'] === 0);
    assert(empty($self_scan['suspicious']));

    // Fast mode scan (skips manifest-verified file).
    $fast_scan = MalwareScanner::scan($tmp_web, [
        'project_root' => $tmp_root,
        'storage_dir'  => $tmp_storage,
        'deep'         => false,
    ]);
    assert($fast_scan['skipped_verified'] === 1);
    assert($fast_scan['scanned'] === 5);

    $flagged_files = array_column($fast_scan['suspicious'], 'file');
    assert(!in_array('web/app/plugins/demo-plugin/clean.php', $flagged_files, true));
    assert(!in_array('web/app/plugins/demo-plugin/manifest-verified.php', $flagged_files, true));
    assert(in_array('web/app/plugins/demo-plugin/webshell.php', $flagged_files, true));
    assert(in_array('web/app/plugins/demo-plugin/logo.php', $flagged_files, true));
    assert(in_array('web/app/uploads/evil.php', $flagged_files, true));
    assert(in_array('web/app/plugins/demo-plugin/eicar.js', $flagged_files, true));

    // Verify executable_in_uploads rule and line/snippet metadata.
    $by_file = [];
    foreach ($fast_scan['findings'] as $f) {
        $by_file[$f['file']] = $f;
    }
    assert($by_file['web/app/uploads/evil.php']['rule_id'] === 'executable_in_uploads');
    assert($by_file['web/app/uploads/evil.php']['severity'] === 'critical');
    assert($by_file['web/app/plugins/demo-plugin/webshell.php']['line'] === 3);
    assert(str_contains($by_file['web/app/plugins/demo-plugin/webshell.php']['snippet'], 'eval'));
    assert($by_file['web/app/plugins/demo-plugin/eicar.js']['rule_id'] === 'known_bad_hash');

    // Deep mode scan (does NOT skip manifest-verified file).
    $deep_scan = MalwareScanner::scan($tmp_web, [
        'project_root' => $tmp_root,
        'storage_dir'  => $tmp_storage,
        'deep'         => true,
    ]);
    $deep_files = array_column($deep_scan['suspicious'], 'file');
    assert(in_array('web/app/plugins/demo-plugin/manifest-verified.php', $deep_files, true));

    // Whitelist test: whitelisting suppresses matching SHA-256, tampering invalidates it.
    $wl_res = MalwareScanner::whitelist_file('web/app/plugins/demo-plugin/webshell.php', $tmp_root, $tmp_storage);
    assert($wl_res['success'] === true);
    assert(array_key_exists('web/app/plugins/demo-plugin/webshell.php', MalwareScanner::get_whitelist($tmp_storage)));

    $after_wl = MalwareScanner::scan($tmp_web, [
        'project_root' => $tmp_root,
        'storage_dir'  => $tmp_storage,
    ]);
    $after_wl_files = array_column($after_wl['suspicious'], 'file');
    assert(!in_array('web/app/plugins/demo-plugin/webshell.php', $after_wl_files, true));

    // Tamper with whitelisted file -> must be flagged again.
    file_put_contents($webshell_file, $webshell_body . "// tampered\n");
    $after_tamper = MalwareScanner::scan($tmp_web, [
        'project_root' => $tmp_root,
        'storage_dir'  => $tmp_storage,
    ]);
    $after_tamper_files = array_column($after_tamper['suspicious'], 'file');
    assert(in_array('web/app/plugins/demo-plugin/webshell.php', $after_tamper_files, true));
    assert(MalwareScanner::remove_whitelist('web/app/plugins/demo-plugin/webshell.php', $tmp_storage) === true);

    // Path traversal rejection in quarantine_file()
    $trav1 = MalwareScanner::quarantine_file('../../etc/passwd', $tmp_root, $tmp_storage);
    assert($trav1['success'] === false);
    $trav2 = MalwareScanner::quarantine_file('/etc/passwd', $tmp_root, $tmp_storage);
    assert($trav2['success'] === false);

    // Quarantine -> list -> restore -> verify bytes -> quarantine -> delete
    $orig_bytes = (string) file_get_contents($uploads_evil);
    $q_res      = MalwareScanner::quarantine_file('web/app/uploads/evil.php', $tmp_root, $tmp_storage, 'executable_in_uploads');
    assert($q_res['success'] === true);
    assert(!file_exists($uploads_evil));

    $q_list = MalwareScanner::list_quarantine($tmp_storage);
    assert(count($q_list) === 1);
    $q_id = $q_list[0]['id'];
    assert($q_list[0]['original_rel_path'] === 'web/app/uploads/evil.php');
    assert(file_exists($tmp_storage . '/' . MalwareScanner::QUARANTINE_DIR . '/' . $q_id . '.quarantine'));

    $restored = MalwareScanner::restore_quarantine($q_id, $tmp_storage);
    assert($restored['success'] === true);
    assert(file_exists($uploads_evil));
    assert(file_get_contents($uploads_evil) === $orig_bytes);
    assert(count(MalwareScanner::list_quarantine($tmp_storage)) === 0);

    $q_res2 = MalwareScanner::quarantine_file('web/app/uploads/evil.php', $tmp_root, $tmp_storage, 'executable_in_uploads');
    assert($q_res2['success'] === true);
    $q_id2 = $q_res2['item']['id'];
    $del   = MalwareScanner::delete_quarantine($q_id2, $tmp_storage);
    assert($del['success'] === true);
    assert(!file_exists($tmp_storage . '/' . MalwareScanner::QUARANTINE_DIR . '/' . $q_id2 . '.quarantine'));
    assert(count(MalwareScanner::list_quarantine($tmp_storage)) === 0);

    // 5. SecurityAudit::run()
    $audit = SecurityAudit::run($tmp_root, $tmp_storage);
    assert(is_int($audit['score']));
    assert($audit['score'] >= 0 && $audit['score'] <= 100);
    assert(in_array($audit['grade'], ['A', 'B', 'C', 'D', 'F'], true));
    assert($audit['counts']['total'] === 14);
    assert(count($audit['checks']) === 14);
    foreach ($audit['checks'] as $chk) {
        assert(!empty($chk['id']) && !empty($chk['label']));
        assert(in_array($chk['status'], ['pass', 'warn', 'fail'], true));
        assert(is_int($chk['weight']) && $chk['weight'] > 0);
        assert(is_bool($chk['can_auto_fix']));
        assert(array_key_exists('fix_hint', $chk));
    }

    echo "All security engine assertions passed!\n";
} finally {
    rm_rf($tmp_root);
}
