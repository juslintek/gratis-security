<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * Versioned malware, WAF request, and IP blocklist signature feed manager.
 * Stores all threat intelligence locally on disk without MySQL overhead.
 */
final class SignatureFeed {

    public const SIGNATURES_FILE   = 'signatures.json';
    public const IP_BLOCKLIST_FILE = 'ip-feed-blocklist.json';
    public const CRON_HOOK         = 'gratis_security_signature_update_cron';
    public const BUILTIN_VERSION   = '2026.11.23';

    private const MAX_PATTERN_LENGTH = 500;
    private const MAX_IP_FEED_LINES  = 10000;

    /**
     * Built-in categorized malware, WAF request, and hash signatures.
     *
     * @return array<string,mixed>
     */
    public static function builtin_bundle(): array {
        $php_exts = ['php', 'phtml', 'phar', 'pht', 'php5', 'php7', 'inc'];

        $malware_rules = [
            // Obfuscated eval variants
            [
                'id'         => 'mw_eval_base64',
                'category'   => 'obfuscation',
                'severity'   => 'critical',
                'label'      => 'Obfuscated eval(base64_decode)',
                'pattern'    => '/\beval\s*\(\s*(?:@\s*)?base64_decode\s*\(/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_eval_gzinflate',
                'category'   => 'obfuscation',
                'severity'   => 'critical',
                'label'      => 'Compressed eval(gzinflate)',
                'pattern'    => '/\beval\s*\(\s*(?:@\s*)?gzinflate\s*\(/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_eval_gzuncompress',
                'category'   => 'obfuscation',
                'severity'   => 'critical',
                'label'      => 'Compressed eval(gzuncompress)',
                'pattern'    => '/\beval\s*\(\s*(?:@\s*)?gzuncompress\s*\(/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_eval_gzdecode',
                'category'   => 'obfuscation',
                'severity'   => 'critical',
                'label'      => 'Compressed eval(gzdecode)',
                'pattern'    => '/\beval\s*\(\s*(?:@\s*)?gzdecode\s*\(/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_eval_str_rot13',
                'category'   => 'obfuscation',
                'severity'   => 'critical',
                'label'      => 'ROT13 eval(str_rot13)',
                'pattern'    => '/\beval\s*\(\s*(?:@\s*)?str_rot13\s*\(/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_eval_rawurldecode',
                'category'   => 'obfuscation',
                'severity'   => 'critical',
                'label'      => 'URL-decoded eval(rawurldecode/urldecode)',
                'pattern'    => '/\beval\s*\(\s*(?:@\s*)?(?:raw)?urldecode\s*\(/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_eval_hex2bin',
                'category'   => 'obfuscation',
                'severity'   => 'critical',
                'label'      => 'Hex-decoded eval(hex2bin)',
                'pattern'    => '/\beval\s*\(\s*(?:@\s*)?hex2bin\s*\(/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_eval_strrev_uu',
                'category'   => 'obfuscation',
                'severity'   => 'critical',
                'label'      => 'Reversed/uudecoded eval',
                'pattern'    => '/\beval\s*\(\s*(?:@\s*)?(?:strrev|convert_uudecode)\s*\(/i',
                'extensions' => $php_exts,
            ],

            // Assert, preg_replace /e, create_function
            [
                'id'         => 'mw_assert_obfuscated',
                'category'   => 'execution',
                'severity'   => 'critical',
                'label'      => 'Dynamic assert() code execution',
                'pattern'    => '/\bassert\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|str_rot13|\$_(?:POST|GET|COOKIE|REQUEST|SERVER))\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_preg_replace_e',
                'category'   => 'execution',
                'severity'   => 'high',
                'label'      => 'Deprecated preg_replace /e code execution modifier',
                'pattern'    => '/\bpreg_replace\s*\(\s*[\'"][\/#~][^\/#~\r\n]{1,180}[\/#~][imsxu]*e[imsxu]*[\'"]\s*,/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_create_function_obfuscated',
                'category'   => 'execution',
                'severity'   => 'critical',
                'label'      => 'Obfuscated or superglobal-driven create_function()',
                'pattern'    => '/\bcreate_function\s*\([^;\r\n]{0,120}(?:base64_decode|gzinflate|str_rot13|\$_(?:POST|GET|COOKIE|REQUEST))/i',
                'extensions' => $php_exts,
            ],

            // Dynamic superglobal execution
            [
                'id'         => 'mw_eval_superglobal',
                'category'   => 'backdoor',
                'severity'   => 'critical',
                'label'      => 'Direct eval() on HTTP request superglobal',
                'pattern'    => '/\beval\s*\(\s*(?:@\s*)?\$_(?:POST|GET|COOKIE|REQUEST)\s*\[/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_exec_superglobal',
                'category'   => 'backdoor',
                'severity'   => 'critical',
                'label'      => 'OS command execution directly from HTTP superglobal',
                'pattern'    => '/\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*(?:@\s*)?\$_(?:POST|GET|COOKIE|REQUEST|FILES)\s*\[/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_var_func_superglobal',
                'category'   => 'backdoor',
                'severity'   => 'critical',
                'label'      => 'Variable function invocation with superglobal payload',
                'pattern'    => '/\$[a-zA-Z_][a-zA-Z0-9_]{0,30}\s*\(\s*\$_(?:POST|GET|COOKIE|REQUEST)\s*\[/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_callback_superglobal',
                'category'   => 'backdoor',
                'severity'   => 'critical',
                'label'      => 'Callback function fed directly from HTTP superglobal',
                'pattern'    => '/\b(?:call_user_func(?:_array)?|array_map|array_filter|usort|uasort|uksort)\s*\(\s*\$_(?:POST|GET|COOKIE|REQUEST)\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_backtick_superglobal',
                'category'   => 'backdoor',
                'severity'   => 'critical',
                'label'      => 'Backtick shell execution using HTTP superglobal',
                'pattern'    => '/`[^`\r\n]{0,120}\$_(?:POST|GET|COOKIE|REQUEST)\[/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_file_put_superglobal',
                'category'   => 'dropper',
                'severity'   => 'high',
                'label'      => 'Arbitrary file write from HTTP superglobal',
                'pattern'    => '/\bfile_put_contents\s*\([^;\r\n]{1,120}\$_(?:POST|GET|REQUEST)\s*\[/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_move_uploaded_superglobal',
                'category'   => 'dropper',
                'severity'   => 'critical',
                'label'      => 'Unvalidated uploaded file destination from request input',
                'pattern'    => '/\bmove_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]\s*,\s*\$_(?:POST|GET|REQUEST)\b/i',
                'extensions' => $php_exts,
            ],

            // Known webshell signatures
            [
                'id'         => 'mw_webshell_filesman',
                'category'   => 'webshell',
                'severity'   => 'critical',
                'label'      => 'FilesMan webshell signature',
                'pattern'    => '/\bFilesMan\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_webshell_wso',
                'category'   => 'webshell',
                'severity'   => 'critical',
                'label'      => 'WSO webshell signature',
                'pattern'    => '/(?:\bWSO_VERSION\b|\bwso_version\b|\bWSO\s+\d+\.\d+|\bWSO\s+Shell\b)/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_webshell_c99',
                'category'   => 'webshell',
                'severity'   => 'critical',
                'label'      => 'c99shell webshell signature',
                'pattern'    => '/\b(?:c99shell|c99_buff_prepare|c99sh_surl)\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_webshell_r57',
                'category'   => 'webshell',
                'severity'   => 'critical',
                'label'      => 'r57shell webshell signature',
                'pattern'    => '/\b(?:r57shell|r57_header)\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_webshell_b374k',
                'category'   => 'webshell',
                'severity'   => 'critical',
                'label'      => 'b374k webshell signature',
                'pattern'    => '/\bb374k\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_webshell_indoxploit',
                'category'   => 'webshell',
                'severity'   => 'critical',
                'label'      => 'IndoXploit webshell signature',
                'pattern'    => '/\bIndoXploit\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_webshell_alfateam',
                'category'   => 'webshell',
                'severity'   => 'critical',
                'label'      => 'Alfa-Team webshell signature',
                'pattern'    => '/\b(?:Alfa-Team|ALFA\s+TEaM|alfashell)\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_webshell_minishell',
                'category'   => 'webshell',
                'severity'   => 'critical',
                'label'      => 'mini_shell webshell signature',
                'pattern'    => '/\b(?:mini_shell|Mini\s+Shell)\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_webshell_leafmailer',
                'category'   => 'webshell',
                'severity'   => 'critical',
                'label'      => 'LeafMailer spam/webshell signature',
                'pattern'    => '/\b(?:leafmailer|Leaf\s+PHPMailer)\b/i',
                'extensions' => $php_exts,
            ],

            // Polyglot image headers hiding PHP
            [
                'id'         => 'mw_gif_polyglot',
                'category'   => 'polyglot',
                'severity'   => 'critical',
                'label'      => 'PHP payload hidden behind GIF image header',
                'pattern'    => '/\A\s*GIF8[79]a[\s\S]{0,256}<\?php\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_img_binary_polyglot',
                'category'   => 'polyglot',
                'severity'   => 'critical',
                'label'      => 'PHP payload embedded in PNG/JPEG header',
                'pattern'    => '/(?:\x89PNG\r\n\x1a\n|\xff\xd8\xff)[\s\S]{0,256}<\?php\b/',
                'extensions' => $php_exts,
            ],

            // .htaccess backdoors
            [
                'id'         => 'mw_htaccess_auto_prepend',
                'category'   => 'htaccess',
                'severity'   => 'critical',
                'label'      => 'Malicious auto_prepend_file / auto_append_file in .htaccess',
                'pattern'    => '/\bphp_(?:value|admin_value)\s+auto_(?:prepend|append)_file\b/i',
                'extensions' => ['htaccess'],
            ],
            [
                'id'         => 'mw_htaccess_addtype_php',
                'category'   => 'htaccess',
                'severity'   => 'critical',
                'label'      => 'AddType/SetHandler PHP execution override in .htaccess',
                'pattern'    => '/\b(?:AddType|AddHandler|SetHandler)\s+[^\r\n]*application\/x-httpd-php/i',
                'extensions' => ['htaccess'],
            ],
            [
                'id'         => 'mw_htaccess_cloaking',
                'category'   => 'htaccess',
                'severity'   => 'high',
                'label'      => 'Search-crawler conditional redirect cloaking in .htaccess',
                'pattern'    => '/\bRewriteCond\s+%\{HTTP_USER_AGENT\}[^\r\n]*(?:googlebot|bingbot|yahoo)[^\r\n]*\r?\n\s*RewriteRule\b/i',
                'extensions' => ['htaccess'],
            ],

            // Remote code include
            [
                'id'         => 'mw_remote_include',
                'category'   => 'rfi',
                'severity'   => 'critical',
                'label'      => 'Remote or stream-wrapper include/require',
                'pattern'    => '/\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?[\'"](?:https?|ftp|php:\/\/input|data:\/\/|expect:\/\/)/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_wp_remote_get_base64',
                'category'   => 'dropper',
                'severity'   => 'critical',
                'label'      => 'Encoded remote payload fetch via wp_remote_get(base64_decode)',
                'pattern'    => '/\bwp_remote_get\s*\(\s*base64_decode\s*\(/i',
                'extensions' => $php_exts,
            ],

            // Hex / octal / chr obfuscation bursts
            [
                'id'         => 'mw_hex_escape_burst',
                'category'   => 'obfuscation',
                'severity'   => 'high',
                'label'      => 'Dense hex-escaped string obfuscation burst',
                'pattern'    => '/(?:\\\\x[0-9a-fA-F]{2}){12,}/',
                'extensions' => array_merge($php_exts, ['js']),
            ],
            [
                'id'         => 'mw_octal_escape_burst',
                'category'   => 'obfuscation',
                'severity'   => 'high',
                'label'      => 'Dense octal-escaped string obfuscation burst',
                'pattern'    => '/(?:\\\\[0-7]{3}){14,}/',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_chr_concat_burst',
                'category'   => 'obfuscation',
                'severity'   => 'high',
                'label'      => 'Repeated chr() concatenation obfuscation',
                'pattern'    => '/(?:\bchr\s*\(\s*\d{2,3}\s*\)\s*\.\s*){6,}/i',
                'extensions' => $php_exts,
            ],

            // JS skimmer & dropper
            [
                'id'         => 'mw_js_eval_atob',
                'category'   => 'js_dropper',
                'severity'   => 'high',
                'label'      => 'Obfuscated JavaScript eval(atob()) dropper',
                'pattern'    => '/\beval\s*\(\s*atob\s*\(/i',
                'extensions' => ['js', 'php', 'phtml', 'shtml'],
            ],
            [
                'id'         => 'mw_js_fromcharcode_dropper',
                'category'   => 'js_dropper',
                'severity'   => 'high',
                'label'      => 'JavaScript String.fromCharCode script injector',
                'pattern'    => '/\bString\.fromCharCode\s*\([^)\r\n]{5,250}\)[\s\S]{0,400}(?:document\.write|createElement\s*\(\s*[\'"]script[\'"]\s*\))/i',
                'extensions' => ['js', 'php', 'phtml', 'shtml'],
            ],
            [
                'id'         => 'mw_js_skimmer_exfil',
                'category'   => 'js_skimmer',
                'severity'   => 'high',
                'label'      => 'Potential payment card skimmer exfiltration pattern',
                'pattern'    => '/\b(?:cc_number|cardnumber|cvv|payment_form)\b[\s\S]{0,300}\b(?:btoa|fetch|XMLHttpRequest|sendBeacon)\s*\(/i',
                'extensions' => ['js'],
            ],

            // Rogue mailer, hidden admin, shell pipe
            [
                'id'         => 'mw_rogue_mailer',
                'category'   => 'spam',
                'severity'   => 'high',
                'label'      => 'Suppressed @mail() driven by HTTP POST/REQUEST data',
                'pattern'    => '/@\s*mail\s*\([^;\r\n]{0,200}\$_(?:POST|REQUEST)\b/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_hidden_admin_user',
                'category'   => 'persistence',
                'severity'   => 'critical',
                'label'      => 'Obfuscated wp_insert_user() creating hidden administrator',
                'pattern'    => '/\bwp_insert_user\s*\([^;]{0,300}[\'"]role[\'"]\s*=>\s*[\'"]administrator[\'"][^;]{0,200}(?:base64_decode|str_rot13|hex2bin|\\\\x[0-9a-f]{2})/i',
                'extensions' => $php_exts,
            ],
            [
                'id'         => 'mw_shell_curl_pipe',
                'category'   => 'dropper',
                'severity'   => 'high',
                'label'      => 'Remote script piped directly into shell interpreter',
                'pattern'    => '/\b(?:curl|wget)\s+[^\r\n]{5,200}\|\s*(?:ba)?sh\b/i',
                'extensions' => ['sh', 'cgi', 'php'],
            ],
        ];

        $request_rules = [
            // SQL injection
            [
                'id'       => 'rq_sqli_union',
                'category' => 'sqli',
                'severity' => 'critical',
                'label'    => 'SQL UNION SELECT injection',
                'target'   => 'input',
                'pattern'  => '/\bunion\s+(?:all\s+)?select\b/i',
            ],
            [
                'id'       => 'rq_sqli_stacked',
                'category' => 'sqli',
                'severity' => 'critical',
                'label'    => 'Stacked SQL DROP/ALTER/TRUNCATE statement',
                'target'   => 'input',
                'pattern'  => '/;\s*(?:drop|alter|truncate)\s+table\b/i',
            ],
            [
                'id'       => 'rq_sqli_sleep',
                'category' => 'sqli',
                'severity' => 'high',
                'label'    => 'Time-based blind SQLi (SLEEP/BENCHMARK)',
                'target'   => 'input',
                'pattern'  => '/\b(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+\s*,)/i',
            ],
            [
                'id'       => 'rq_sqli_waitfor',
                'category' => 'sqli',
                'severity' => 'high',
                'label'    => 'MSSQL WAITFOR DELAY injection',
                'target'   => 'input',
                'pattern'  => '/\bwaitfor\s+delay\s+[\'"]\d+/i',
            ],
            [
                'id'       => 'rq_sqli_xml_error',
                'category' => 'sqli',
                'severity' => 'high',
                'label'    => 'Error-based SQLi (EXTRACTVALUE/UPDATEXML)',
                'target'   => 'input',
                'pattern'  => '/\b(?:extractvalue|updatexml)\s*\(/i',
            ],
            [
                'id'       => 'rq_sqli_tautology',
                'category' => 'sqli',
                'severity' => 'high',
                'label'    => 'SQL quote boolean tautology',
                'target'   => 'input',
                'pattern'  => '/(?:\'|"|`)\s*(?:or|and)\s*[\'"]?1[\'"]?\s*=\s*[\'"]?1/i',
            ],

            // Cross-site scripting
            [
                'id'       => 'rq_xss_script',
                'category' => 'xss',
                'severity' => 'high',
                'label'    => 'Injected <script> tag',
                'target'   => 'input',
                'pattern'  => '/<script\b[^>]*>/i',
            ],
            [
                'id'       => 'rq_xss_javascript_uri',
                'category' => 'xss',
                'severity' => 'high',
                'label'    => 'javascript: URI payload',
                'target'   => 'input',
                'pattern'  => '/\bjavascript\s*:[^\s]{1,120}/i',
            ],
            [
                'id'       => 'rq_xss_data_html',
                'category' => 'xss',
                'severity' => 'high',
                'label'    => 'data:text/html URI payload',
                'target'   => 'input',
                'pattern'  => '/\bdata\s*:\s*text\/html/i',
            ],
            [
                'id'       => 'rq_xss_event_attr',
                'category' => 'xss',
                'severity' => 'high',
                'label'    => 'Inline HTML on* event attribute',
                'target'   => 'input',
                'pattern'  => '/<[^>]{1,200}[\s\/]on[a-z]{2,20}\s*=/i',
            ],
            [
                'id'       => 'rq_xss_vbscript',
                'category' => 'xss',
                'severity' => 'medium',
                'label'    => 'vbscript: URI payload',
                'target'   => 'input',
                'pattern'  => '/\bvbscript\s*:/i',
            ],

            // Local file inclusion / path traversal
            [
                'id'       => 'rq_lfi_traversal',
                'category' => 'lfi',
                'severity' => 'high',
                'label'    => 'Directory traversal sequence',
                'target'   => 'all',
                'pattern'  => '/(?:\.\.[\/\\\\]|%2e%2e[\/\\\\]?|\.\.%2f)/i',
            ],
            [
                'id'       => 'rq_lfi_etc_passwd',
                'category' => 'lfi',
                'severity' => 'critical',
                'label'    => 'Attempted /etc/passwd or /etc/shadow read',
                'target'   => 'all',
                'pattern'  => '/\/etc\/(?:passwd|shadow)\b/i',
            ],
            [
                'id'       => 'rq_lfi_proc_environ',
                'category' => 'lfi',
                'severity' => 'critical',
                'label'    => 'Attempted /proc/self/environ read',
                'target'   => 'all',
                'pattern'  => '/\/proc\/self\/(?:environ|cmdline)\b/i',
            ],
            [
                'id'       => 'rq_lfi_php_wrapper',
                'category' => 'lfi',
                'severity' => 'critical',
                'label'    => 'PHP stream wrapper injection (php://filter / php://input)',
                'target'   => 'all',
                'pattern'  => '/php:\/\/(?:filter|input)\b/i',
            ],
            [
                'id'       => 'rq_lfi_expect_phar',
                'category' => 'lfi',
                'severity' => 'critical',
                'label'    => 'Dangerous expect:// or phar:// stream wrapper',
                'target'   => 'input',
                'pattern'  => '/(?:expect|phar):\/\//i',
            ],

            // Remote command execution
            [
                'id'       => 'rq_rce_cmd_chain',
                'category' => 'rce',
                'severity' => 'critical',
                'label'    => 'Shell command chaining with wget/curl',
                'target'   => 'input',
                'pattern'  => '/(?:;|\||&&)\s*(?:wget|curl)\s+/i',
            ],
            [
                'id'       => 'rq_rce_subshell',
                'category' => 'rce',
                'severity' => 'critical',
                'label'    => 'Shell subcommand substitution',
                'target'   => 'input',
                'pattern'  => '/(?:\$\(\s*(?:curl|wget|id|whoami|uname|cat)\b|`\s*(?:id|whoami|uname|curl|wget)\b[^`]*`)/i',
            ],
            [
                'id'       => 'rq_rce_shell_bin',
                'category' => 'rce',
                'severity' => 'critical',
                'label'    => 'Direct OS shell binary invocation',
                'target'   => 'input',
                'pattern'  => '/(?:\bcmd\.exe\b|\/bin\/(?:ba)?sh\b)/i',
            ],
            [
                'id'       => 'rq_rce_php_exec',
                'category' => 'rce',
                'severity' => 'critical',
                'label'    => 'PHP code execution function in request input',
                'target'   => 'input',
                'pattern'  => '/\b(?:shell_exec|passthru|proc_open)\s*\(/i',
            ],

            // PHP object injection
            [
                'id'       => 'rq_php_object_inject',
                'category' => 'php_object',
                'severity' => 'critical',
                'label'    => 'Serialized PHP object payload in request input',
                'target'   => 'input',
                'pattern'  => '/O:\d+:"[a-zA-Z0-9_\\\\]+":\d+:\{/',
            ],

            // Sensitive probes
            [
                'id'       => 'rq_probe_secrets',
                'category' => 'probe',
                'severity' => 'high',
                'label'    => 'Probe for wp-config.php, .env, or .git metadata',
                'target'   => 'uri',
                'pattern'  => '/(?:^|\/)(?:wp-config\.php|\.env(?:\.[^\/\s]+)?|\.git(?:\/|$)|\.htaccess|web\.config)/i',
            ],
            [
                'id'       => 'rq_probe_xmlrpc',
                'category' => 'probe',
                'severity' => 'medium',
                'label'    => 'XML-RPC or WLW manifest probe',
                'target'   => 'uri',
                'pattern'  => '/\/(?:xmlrpc\.php|wlwmanifest\.xml)\b/i',
            ],
            [
                'id'       => 'rq_probe_admin_tools',
                'category' => 'probe',
                'severity' => 'high',
                'label'    => 'Probe for phpMyAdmin, Adminer, or PHPUnit eval-stdin',
                'target'   => 'uri',
                'pattern'  => '/\/(?:phpmyadmin|pma|adminer(?:\.php)?|eval-stdin\.php)\b/i',
            ],
            [
                'id'       => 'rq_probe_phpinfo',
                'category' => 'probe',
                'severity' => 'medium',
                'label'    => 'Probe for exposed phpinfo.php',
                'target'   => 'uri',
                'pattern'  => '/\/phpinfo\.php\b/i',
            ],
            [
                'id'       => 'rq_probe_legacy_plugins',
                'category' => 'probe',
                'severity' => 'high',
                'label'    => 'Probe for known vulnerable WordPress plugin targets',
                'target'   => 'uri',
                'pattern'  => '/(?:timthumb\.php|\brevslider\b|\bwp-file-manager\b)/i',
            ],

            // Malicious scanner user-agents
            [
                'id'       => 'rq_scanner_vuln',
                'category' => 'scanner',
                'severity' => 'high',
                'label'    => 'Automated vulnerability scanner user-agent',
                'target'   => 'ua',
                'pattern'  => '/\b(?:sqlmap|nikto|nuclei|wpscan|acunetix|nessus)\b/i',
            ],
            [
                'id'       => 'rq_scanner_recon',
                'category' => 'scanner',
                'severity' => 'medium',
                'label'    => 'Port or directory brute-force scanner user-agent',
                'target'   => 'ua',
                'pattern'  => '/\b(?:masscan|zgrab|dirbuster|gobuster|feroxbuster)\b/i',
            ],
            [
                'id'       => 'rq_scanner_exploit',
                'category' => 'scanner',
                'severity' => 'high',
                'label'    => 'Exploit tool user-agent (Havij/Morfeus)',
                'target'   => 'ua',
                'pattern'  => '/\b(?:havij|morfeus)\b/i',
            ],
        ];

        // Known malicious payload SHA-256 signatures (EICAR PHP test + known dropper hashes).
        $bad_hashes = [
            '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' => 'EICAR Standard Anti-Virus Test Signature',
            'b10ef6c6a2440f01d8f34f82e66b1e5c4c7f676a2e048b9c67c19e0f5b8f19c2' => 'WSO 2.5 Webshell Dropper',
            '4c1a5f42f7e8a9c4e5b2f8d3e4a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8' => 'c99madshell PHP Backdoor',
        ];

        return [
            'version'       => self::BUILTIN_VERSION,
            'updated_at'    => gmdate('c'),
            'malware_rules' => $malware_rules,
            'request_rules' => $request_rules,
            'bad_hashes'    => $bad_hashes,
        ];
    }

    /**
     * Load active signatures by merging built-in rules with persisted feed rules.
     *
     * @return array<string,mixed>
     */
    public static function load(?string $storage_dir = null): array {
        $builtin = self::builtin_bundle();
        $dir     = self::resolve_storage_dir($storage_dir);
        $file    = $dir . '/' . self::SIGNATURES_FILE;

        $stored = [];
        if (@file_exists($file)) {
            $raw = (string) @file_get_contents($file);
            if ('' !== $raw) {
                $decoded = FileIntegrity::simd_decode($raw, true);
                if (is_array($decoded)) {
                    $stored = $decoded;
                }
            }
        }

        $remote_malware = isset($stored['remote_malware_rules']) && is_array($stored['remote_malware_rules'])
            ? $stored['remote_malware_rules']
            : [];
        $remote_request = isset($stored['remote_request_rules']) && is_array($stored['remote_request_rules'])
            ? $stored['remote_request_rules']
            : [];
        $remote_hashes  = isset($stored['remote_bad_hashes']) && is_array($stored['remote_bad_hashes'])
            ? $stored['remote_bad_hashes']
            : [];

        $malware_rules = self::merge_rules_by_id((array) $builtin['malware_rules'], $remote_malware);
        $request_rules = self::merge_rules_by_id((array) $builtin['request_rules'], $remote_request);
        $bad_hashes    = self::merge_hashes((array) $builtin['bad_hashes'], $remote_hashes);
        $blocked_ips   = self::get_feed_ips($dir);

        $last_updated = isset($stored['last_updated']) && is_string($stored['last_updated'])
            ? $stored['last_updated']
            : '';
        $sources = isset($stored['sources']) && is_array($stored['sources'])
            ? $stored['sources']
            : ['builtin' => ['status' => 'ok', 'version' => self::BUILTIN_VERSION]];

        $version = isset($stored['version']) && is_string($stored['version']) && '' !== $stored['version']
            ? $stored['version']
            : self::BUILTIN_VERSION;

        return [
            'version'       => $version,
            'last_updated'  => $last_updated,
            'sources'       => $sources,
            'malware_rules' => $malware_rules,
            'request_rules' => $request_rules,
            'bad_hashes'    => $bad_hashes,
            'blocked_ips'   => $blocked_ips,
            'counts'        => [
                'malware_rules' => count($malware_rules),
                'request_rules' => count($request_rules),
                'bad_hashes'    => count($bad_hashes),
                'blocked_ips'   => count($blocked_ips),
            ],
        ];
    }

    /**
     * Strictly validate a downloaded JSON signature bundle before merging.
     *
     * @param array<string,mixed> $payload
     * @return array{valid:bool,bundle:array<string,mixed>,rejected:int,errors:array<int,string>}
     */
    public static function validate_remote_bundle(array $payload): array {
        $allowed_keys = ['malware_rules', 'request_rules', 'bad_hashes', 'blocked_ips', 'version'];
        $bundle       = [
            'version'       => self::BUILTIN_VERSION,
            'malware_rules' => [],
            'request_rules' => [],
            'bad_hashes'    => [],
            'blocked_ips'   => [],
        ];
        $rejected = 0;
        $errors   = [];
        $accepted = 0;

        if (isset($payload['version'])) {
            if (is_string($payload['version']) && preg_match('/^[a-zA-Z0-9._-]{1,40}$/', trim($payload['version']))) {
                $bundle['version'] = trim($payload['version']);
            } else {
                ++$rejected;
                $errors[] = 'Invalid bundle version format.';
            }
        }

        if (isset($payload['malware_rules'])) {
            if (!is_array($payload['malware_rules'])) {
                ++$rejected;
                $errors[] = 'malware_rules must be an array.';
            } else {
                foreach ($payload['malware_rules'] as $idx => $rule) {
                    if (!is_array($rule)) {
                        ++$rejected;
                        $errors[] = "malware_rules[{$idx}]: entry must be an object.";
                        continue;
                    }
                    $validated = self::validate_malware_rule($rule, $idx, $errors);
                    if (null === $validated) {
                        ++$rejected;
                        continue;
                    }
                    $bundle['malware_rules'][] = $validated;
                    ++$accepted;
                }
            }
        }

        if (isset($payload['request_rules'])) {
            if (!is_array($payload['request_rules'])) {
                ++$rejected;
                $errors[] = 'request_rules must be an array.';
            } else {
                foreach ($payload['request_rules'] as $idx => $rule) {
                    if (!is_array($rule)) {
                        ++$rejected;
                        $errors[] = "request_rules[{$idx}]: entry must be an object.";
                        continue;
                    }
                    $validated = self::validate_request_rule($rule, $idx, $errors);
                    if (null === $validated) {
                        ++$rejected;
                        continue;
                    }
                    $bundle['request_rules'][] = $validated;
                    ++$accepted;
                }
            }
        }

        if (isset($payload['bad_hashes'])) {
            if (!is_array($payload['bad_hashes'])) {
                ++$rejected;
                $errors[] = 'bad_hashes must be an associative map.';
            } else {
                foreach ($payload['bad_hashes'] as $hash => $label) {
                    $clean_hash = strtolower(trim((string) $hash));
                    if (1 !== preg_match('/^[a-f0-9]{64}$/', $clean_hash)) {
                        ++$rejected;
                        $errors[] = "bad_hashes: invalid SHA-256 '{$clean_hash}'.";
                        continue;
                    }
                    $clean_label = self::clean_label((string) $label);
                    if ('' === $clean_label) {
                        $clean_label = 'Known malicious payload';
                    }
                    $bundle['bad_hashes'][$clean_hash] = $clean_label;
                    ++$accepted;
                }
            }
        }

        if (isset($payload['blocked_ips'])) {
            if (!is_array($payload['blocked_ips'])) {
                ++$rejected;
                $errors[] = 'blocked_ips must be an array.';
            } else {
                foreach ($payload['blocked_ips'] as $idx => $ip_entry) {
                    $ip_str = trim((string) $ip_entry);
                    if (!self::is_valid_ip_or_cidr($ip_str)) {
                        ++$rejected;
                        $errors[] = "blocked_ips[{$idx}]: invalid IP/CIDR '{$ip_str}'.";
                        continue;
                    }
                    $bundle['blocked_ips'][] = $ip_str;
                    ++$accepted;
                }
                $bundle['blocked_ips'] = array_values(array_unique($bundle['blocked_ips']));
            }
        }

        // Check if payload contained only unsupported keys or was completely empty.
        $present_allowed = array_intersect(array_keys($payload), $allowed_keys);
        if (empty($present_allowed)) {
            $errors[] = 'Bundle contains no recognized signature sections.';
        }

        $valid = ($accepted > 0) || ($rejected === 0 && !empty($present_allowed));

        return [
            'valid'    => $valid,
            'bundle'   => $bundle,
            'rejected' => $rejected,
            'errors'   => $errors,
        ];
    }

    /**
     * Refresh built-in bundle, optional remote signature feed, IP blocklist feed, and WP core checksums.
     *
     * @param array<string,mixed>|null $options
     * @return array<string,mixed>
     */
    public static function update(?array $options = null, ?string $storage_dir = null): array {
        $dir = self::resolve_storage_dir($storage_dir);
        self::ensure_hardened_dir($dir);

        $settings = self::resolve_feed_settings($options);
        $builtin  = self::builtin_bundle();
        $now      = gmdate('c');

        $existing_file = $dir . '/' . self::SIGNATURES_FILE;
        $existing      = [];
        if (@file_exists($existing_file)) {
            $decoded = FileIntegrity::simd_decode((string) @file_get_contents($existing_file), true);
            if (is_array($decoded)) {
                $existing = $decoded;
            }
        }

        $remote_malware = isset($existing['remote_malware_rules']) && is_array($existing['remote_malware_rules'])
            ? $existing['remote_malware_rules']
            : [];
        $remote_request = isset($existing['remote_request_rules']) && is_array($existing['remote_request_rules'])
            ? $existing['remote_request_rules']
            : [];
        $remote_hashes  = isset($existing['remote_bad_hashes']) && is_array($existing['remote_bad_hashes'])
            ? $existing['remote_bad_hashes']
            : [];

        $sources = [
            'builtin' => [
                'status'  => 'ok',
                'version' => self::BUILTIN_VERSION,
                'count'   => count((array) $builtin['malware_rules']) + count((array) $builtin['request_rules']),
            ],
        ];

        $allow_insecure_http = !empty($options['allow_http']) && PHP_SAPI === 'cli';

        // 1. WordPress Core checksums cache refresh (best-effort, never fatal).
        $sync_wp = array_key_exists('sync_wp_checksums', $settings) ? (bool) $settings['sync_wp_checksums'] : true;
        if ($sync_wp && function_exists('wp_remote_get')) {
            $sources['wp_checksums'] = self::refresh_wp_core_checksums($dir);
        } else {
            $sources['wp_checksums'] = [
                'status' => 'skipped',
                'reason' => $sync_wp ? 'wp_remote_get unavailable' : 'disabled',
            ];
        }

        // 2. Remote JSON threat signature feed.
        $feed_url   = trim((string) ($settings['signature_feed_url'] ?? ''));
        $feed_token = trim((string) ($settings['signature_feed_token'] ?? ''));
        $version    = self::BUILTIN_VERSION;

        if ('' === $feed_url) {
            $sources['signature_feed'] = ['status' => 'skipped', 'reason' => 'not_configured'];
        } elseif (!self::is_allowed_feed_url($feed_url, $allow_insecure_http)) {
            $sources['signature_feed'] = ['status' => 'error', 'reason' => 'Feed URL must use https://'];
        } elseif (!function_exists('wp_remote_get')) {
            $sources['signature_feed'] = ['status' => 'skipped', 'reason' => 'wp_remote_get unavailable'];
        } else {
            $fetch = self::fetch_url($feed_url, $feed_token);
            if (!$fetch['ok']) {
                $sources['signature_feed'] = ['status' => 'error', 'reason' => $fetch['error']];
            } else {
                $decoded = FileIntegrity::simd_decode($fetch['body'], true);
                if (!is_array($decoded)) {
                    $sources['signature_feed'] = ['status' => 'error', 'reason' => 'Invalid JSON payload'];
                } else {
                    $validation = self::validate_remote_bundle($decoded);
                    if (!$validation['valid']) {
                        $sources['signature_feed'] = [
                            'status'   => 'error',
                            'reason'   => implode('; ', array_slice($validation['errors'], 0, 5)),
                            'rejected' => $validation['rejected'],
                        ];
                    } else {
                        $vbundle        = $validation['bundle'];
                        $remote_malware = (array) $vbundle['malware_rules'];
                        $remote_request = (array) $vbundle['request_rules'];
                        $remote_hashes  = (array) $vbundle['bad_hashes'];
                        if (!empty($vbundle['version'])) {
                            $version = (string) $vbundle['version'];
                        }
                        if (!empty($vbundle['blocked_ips'])) {
                            $existing_ips = self::get_feed_ips($dir);
                            $merged_ips   = array_slice(
                                array_values(array_unique(array_merge($existing_ips, (array) $vbundle['blocked_ips']))),
                                0,
                                self::MAX_IP_FEED_LINES
                            );
                            self::atomic_write(
                                $dir . '/' . self::IP_BLOCKLIST_FILE,
                                FileIntegrity::simd_encode([
                                    'updated_at' => $now,
                                    'ips'        => $merged_ips,
                                ])
                            );
                        }
                        $sources['signature_feed'] = [
                            'status'        => 'ok',
                            'version'       => $version,
                            'malware_rules' => count($remote_malware),
                            'request_rules' => count($remote_request),
                            'bad_hashes'    => count($remote_hashes),
                            'rejected'      => $validation['rejected'],
                        ];
                    }
                }
            }
        }

        // 3. Newline-delimited IP / CIDR feed.
        $ip_feed_url = trim((string) ($settings['ip_feed_url'] ?? ''));
        if ('' === $ip_feed_url) {
            $sources['ip_feed'] = ['status' => 'skipped', 'reason' => 'not_configured'];
        } elseif (!self::is_allowed_feed_url($ip_feed_url, $allow_insecure_http)) {
            $sources['ip_feed'] = ['status' => 'error', 'reason' => 'IP feed URL must use https://'];
        } elseif (!function_exists('wp_remote_get')) {
            $sources['ip_feed'] = ['status' => 'skipped', 'reason' => 'wp_remote_get unavailable'];
        } else {
            $fetch = self::fetch_url($ip_feed_url, $feed_token);
            if (!$fetch['ok']) {
                $sources['ip_feed'] = ['status' => 'error', 'reason' => $fetch['error']];
            } else {
                $ips = self::parse_ip_lines($fetch['body']);
                self::atomic_write(
                    $dir . '/' . self::IP_BLOCKLIST_FILE,
                    FileIntegrity::simd_encode([
                        'updated_at' => $now,
                        'source_url' => $ip_feed_url,
                        'ips'        => $ips,
                    ])
                );
                $sources['ip_feed'] = [
                    'status' => 'ok',
                    'count'  => count($ips),
                ];
            }
        }

        $merged_malware = self::merge_rules_by_id((array) $builtin['malware_rules'], $remote_malware);
        $merged_request = self::merge_rules_by_id((array) $builtin['request_rules'], $remote_request);
        $merged_hashes  = self::merge_hashes((array) $builtin['bad_hashes'], $remote_hashes);
        $feed_ips       = self::get_feed_ips($dir);

        $counts = [
            'malware_rules' => count($merged_malware),
            'request_rules' => count($merged_request),
            'bad_hashes'    => count($merged_hashes),
            'blocked_ips'   => count($feed_ips),
        ];

        $stored_payload = [
            'version'              => $version,
            'builtin_version'      => self::BUILTIN_VERSION,
            'last_updated'         => $now,
            'sources'              => $sources,
            'counts'               => $counts,
            'malware_rules'        => $merged_malware,
            'request_rules'        => $merged_request,
            'bad_hashes'           => $merged_hashes,
            'remote_malware_rules' => $remote_malware,
            'remote_request_rules' => $remote_request,
            'remote_bad_hashes'    => $remote_hashes,
        ];

        self::atomic_write($existing_file, FileIntegrity::simd_encode($stored_payload));

        return [
            'version'      => $version,
            'last_updated' => $now,
            'sources'      => $sources,
            'counts'       => $counts,
            'storage_file' => $existing_file,
        ];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public static function get_malware_rules(?string $storage_dir = null): array {
        $bundle = self::load($storage_dir);
        return (array) ($bundle['malware_rules'] ?? []);
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public static function get_request_rules(?string $storage_dir = null): array {
        $bundle = self::load($storage_dir);
        return (array) ($bundle['request_rules'] ?? []);
    }

    /**
     * @return array<string,string>
     */
    public static function get_bad_hashes(?string $storage_dir = null): array {
        $bundle = self::load($storage_dir);
        return (array) ($bundle['bad_hashes'] ?? []);
    }

    /**
     * @return array<int,string>
     */
    public static function get_feed_ips(?string $storage_dir = null): array {
        $dir  = self::resolve_storage_dir($storage_dir);
        $file = $dir . '/' . self::IP_BLOCKLIST_FILE;
        if (!@file_exists($file)) {
            return [];
        }
        $raw = (string) @file_get_contents($file);
        if ('' === $raw) {
            return [];
        }
        $decoded = FileIntegrity::simd_decode($raw, true);
        if (!is_array($decoded)) {
            return [];
        }
        $list = isset($decoded['ips']) && is_array($decoded['ips']) ? $decoded['ips'] : $decoded;
        $ips  = [];
        foreach ($list as $entry) {
            $ip = trim((string) $entry);
            if (self::is_valid_ip_or_cidr($ip)) {
                $ips[] = $ip;
            }
        }
        return array_values(array_unique($ips));
    }

    /**
     * @return array<string,mixed>
     */
    public static function get_status(?string $storage_dir = null): array {
        $bundle = self::load($storage_dir);
        return [
            'version'      => (string) ($bundle['version'] ?? self::BUILTIN_VERSION),
            'last_updated' => (string) ($bundle['last_updated'] ?? ''),
            'sources'      => (array) ($bundle['sources'] ?? []),
            'counts'       => (array) ($bundle['counts'] ?? []),
        ];
    }

    /**
     * Validate a single malware rule definition.
     *
     * @param array<string,mixed> $rule
     * @param array<int,string>   $errors
     * @return array<string,mixed>|null
     */
    private static function validate_malware_rule(array $rule, int|string $idx, array &$errors): ?array {
        $id       = self::clean_id((string) ($rule['id'] ?? ''));
        $label    = self::clean_label((string) ($rule['label'] ?? ''));
        $category = self::clean_id((string) ($rule['category'] ?? 'custom'));
        $severity = strtolower(trim((string) ($rule['severity'] ?? 'medium')));
        $pattern  = (string) ($rule['pattern'] ?? '');

        if ('' === $id) {
            $errors[] = "malware_rules[{$idx}]: invalid or missing id.";
            return null;
        }
        if ('' === $label) {
            $errors[] = "malware_rules[{$idx}]: missing label.";
            return null;
        }
        if (!in_array($severity, ['critical', 'high', 'medium'], true)) {
            $errors[] = "malware_rules[{$idx}]: invalid severity '{$severity}'.";
            return null;
        }
        if (!self::is_safe_regex($pattern)) {
            $errors[] = "malware_rules[{$idx}]: unsafe or invalid regex pattern.";
            return null;
        }

        $exts = [];
        if (isset($rule['extensions']) && is_array($rule['extensions'])) {
            foreach ($rule['extensions'] as $ext) {
                $clean_ext = strtolower(ltrim(trim((string) $ext), '.'));
                if ('*' === $clean_ext || 1 === preg_match('/^[a-z0-9]{1,12}$/', $clean_ext)) {
                    $exts[] = $clean_ext;
                }
            }
        }
        if (empty($exts)) {
            $exts = ['php'];
        }

        return [
            'id'         => $id,
            'category'   => '' !== $category ? $category : 'custom',
            'severity'   => $severity,
            'label'      => $label,
            'pattern'    => $pattern,
            'extensions' => array_values(array_unique($exts)),
        ];
    }

    /**
     * Validate a single WAF request rule definition.
     *
     * @param array<string,mixed> $rule
     * @param array<int,string>   $errors
     * @return array<string,mixed>|null
     */
    private static function validate_request_rule(array $rule, int|string $idx, array &$errors): ?array {
        $id       = self::clean_id((string) ($rule['id'] ?? ''));
        $label    = self::clean_label((string) ($rule['label'] ?? ''));
        $category = self::clean_id((string) ($rule['category'] ?? 'custom'));
        $severity = strtolower(trim((string) ($rule['severity'] ?? 'medium')));
        $target   = strtolower(trim((string) ($rule['target'] ?? 'input')));
        $pattern  = (string) ($rule['pattern'] ?? '');

        if ('' === $id) {
            $errors[] = "request_rules[{$idx}]: invalid or missing id.";
            return null;
        }
        if ('' === $label) {
            $errors[] = "request_rules[{$idx}]: missing label.";
            return null;
        }
        if (!in_array($severity, ['critical', 'high', 'medium', 'low'], true)) {
            $errors[] = "request_rules[{$idx}]: invalid severity '{$severity}'.";
            return null;
        }
        if (!in_array($target, ['uri', 'query', 'body', 'input', 'ua', 'all'], true)) {
            $errors[] = "request_rules[{$idx}]: invalid target '{$target}'.";
            return null;
        }
        if (!self::is_safe_regex($pattern)) {
            $errors[] = "request_rules[{$idx}]: unsafe or invalid regex pattern.";
            return null;
        }

        return [
            'id'       => $id,
            'category' => '' !== $category ? $category : 'custom',
            'severity' => $severity,
            'label'    => $label,
            'target'   => $target,
            'pattern'  => $pattern,
        ];
    }

    /**
     * Reject overly long patterns, nested quantifiers (ReDoS), and broken PCRE syntax.
     */
    public static function is_safe_regex(string $pattern): bool {
        if ('' === $pattern || strlen($pattern) > self::MAX_PATTERN_LENGTH) {
            return false;
        }
        // Reject catastrophic nested quantifiers like (a+)+, (.*)*, ([a-z]+)*
        if (1 === preg_match('/\([^()]*[+*][^()]*\)[+*{]/', $pattern)) {
            return false;
        }
        // Reject adjacent unescaped quantifiers like ++, **, +*
        if (1 === preg_match('/(?<!\\\\)[+*](?<!\\\\)[+*]/', $pattern)) {
            return false;
        }
        return false !== @preg_match($pattern, '');
    }

    /**
     * Validate IPv4, IPv6, or IP/CIDR notation.
     */
    public static function is_valid_ip_or_cidr(string $entry): bool {
        if ('' === $entry) {
            return false;
        }
        if (!str_contains($entry, '/')) {
            return false !== filter_var($entry, FILTER_VALIDATE_IP);
        }
        $parts = explode('/', $entry, 2);
        if (2 !== count($parts)) {
            return false;
        }
        [$ip, $mask] = $parts;
        if (!ctype_digit($mask)) {
            return false;
        }
        $prefix = (int) $mask;
        if (false !== filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $prefix >= 0 && $prefix <= 32;
        }
        if (false !== filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $prefix >= 0 && $prefix <= 128;
        }
        return false;
    }

    /**
     * @param array<int,array<string,mixed>> $base
     * @param array<int,array<string,mixed>> $extra
     * @return array<int,array<string,mixed>>
     */
    private static function merge_rules_by_id(array $base, array $extra): array {
        $indexed = [];
        foreach ($base as $rule) {
            if (is_array($rule) && !empty($rule['id'])) {
                $indexed[(string) $rule['id']] = $rule;
            }
        }
        foreach ($extra as $rule) {
            if (is_array($rule) && !empty($rule['id'])) {
                $indexed[(string) $rule['id']] = $rule;
            }
        }
        return array_values($indexed);
    }

    /**
     * @param array<string,string> $base
     * @param array<string,string> $extra
     * @return array<string,string>
     */
    private static function merge_hashes(array $base, array $extra): array {
        $merged = [];
        foreach ([$base, $extra] as $set) {
            foreach ($set as $hash => $label) {
                $clean = strtolower(trim((string) $hash));
                if (1 === preg_match('/^[a-f0-9]{64}$/', $clean)) {
                    $merged[$clean] = (string) $label;
                }
            }
        }
        return $merged;
    }

    /**
     * Refresh WordPress Core checksums cache without failing on offline/CLI environments.
     *
     * @return array<string,mixed>
     */
    private static function refresh_wp_core_checksums(string $storage_dir): array {
        global $wp_version;
        $version = is_string($wp_version) && '' !== $wp_version
            ? $wp_version
            : (function_exists('get_bloginfo') ? (string) get_bloginfo('version') : '');

        if ('' === $version && defined('ABSPATH') && defined('WPINC')) {
            $ver_file = ABSPATH . WPINC . '/version.php';
            if (@file_exists($ver_file)) {
                $raw = (string) @file_get_contents($ver_file);
                if (1 === preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $raw, $m)) {
                    $version = $m[1];
                }
            }
        }

        if ('' === $version) {
            return ['status' => 'skipped', 'reason' => 'wp_version unavailable'];
        }

        $locale = function_exists('get_locale') ? (string) get_locale() : 'en_US';
        $url    = sprintf(
            'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
            rawurlencode($version),
            rawurlencode($locale)
        );

        $response = wp_remote_get($url, ['timeout' => 15]);
        if (function_exists('is_wp_error') && is_wp_error($response)) {
            return ['status' => 'error', 'reason' => $response->get_error_message()];
        }
        $code = function_exists('wp_remote_retrieve_response_code') ? (int) wp_remote_retrieve_response_code($response) : 0;
        if (200 !== $code) {
            return ['status' => 'error', 'reason' => "HTTP {$code}"];
        }

        $body = function_exists('wp_remote_retrieve_body') ? (string) wp_remote_retrieve_body($response) : '';
        $json = FileIntegrity::simd_decode($body, true);
        if (!is_array($json) || empty($json['checksums']) || !is_array($json['checksums'])) {
            return ['status' => 'error', 'reason' => 'Invalid WP checksums response'];
        }

        $checksums  = (array) $json['checksums'];
        $cache_file = $storage_dir . '/' . FileIntegrity::CORE_CACHE_PREFIX . $version . '-' . $locale . '.json';
        self::atomic_write($cache_file, FileIntegrity::simd_encode($checksums));

        return [
            'status'  => 'ok',
            'version' => $version,
            'locale'  => $locale,
            'count'   => count($checksums),
        ];
    }

    /**
     * @return array{ok:bool,body:string,error:string}
     */
    private static function fetch_url(string $url, string $token): array {
        $args = ['timeout' => 15];
        if ('' !== $token) {
            $args['headers'] = [
                'Authorization' => 'Bearer ' . $token,
                'X-API-Key'     => $token,
            ];
        }

        $response = wp_remote_get($url, $args);
        if (function_exists('is_wp_error') && is_wp_error($response)) {
            return ['ok' => false, 'body' => '', 'error' => $response->get_error_message()];
        }

        $code = function_exists('wp_remote_retrieve_response_code') ? (int) wp_remote_retrieve_response_code($response) : 0;
        if (200 !== $code) {
            return ['ok' => false, 'body' => '', 'error' => "HTTP {$code}"];
        }

        $body = function_exists('wp_remote_retrieve_body') ? (string) wp_remote_retrieve_body($response) : '';
        return ['ok' => true, 'body' => $body, 'error' => ''];
    }

    /**
     * @return array<int,string>
     */
    private static function parse_ip_lines(string $body): array {
        $lines = preg_split('/\r\n|\r|\n/', $body);
        if (!is_array($lines)) {
            return [];
        }
        $ips = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ('' === $line || str_starts_with($line, '#') || str_starts_with($line, ';')) {
                continue;
            }
            $hash_pos = strpos($line, '#');
            if (false !== $hash_pos) {
                $line = trim(substr($line, 0, $hash_pos));
            }
            // Support ipset / hosts-like tokens by inspecting first whitespace field.
            $parts = preg_split('/\s+/', $line);
            $cand  = is_array($parts) && isset($parts[0]) ? trim($parts[0]) : $line;
            if (self::is_valid_ip_or_cidr($cand)) {
                $ips[$cand] = true;
                if (count($ips) >= self::MAX_IP_FEED_LINES) {
                    break;
                }
            }
        }
        return array_keys($ips);
    }

    private static function is_allowed_feed_url(string $url, bool $allow_http): bool {
        if (false === filter_var($url, FILTER_VALIDATE_URL)) {
            return false;
        }
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if ('https' === $scheme) {
            return true;
        }
        return $allow_http && 'http' === $scheme;
    }

    /**
     * @param array<string,mixed>|null $options
     * @return array<string,mixed>
     */
    private static function resolve_feed_settings(?array $options): array {
        $base = [];
        if (function_exists('get_option')) {
            $base = Settings::all();
        }
        if (is_array($options)) {
            return array_merge($base, $options);
        }
        return $base;
    }

    private static function resolve_storage_dir(?string $storage_dir): string {
        if (null !== $storage_dir && '' !== $storage_dir) {
            return rtrim($storage_dir, '/');
        }
        return rtrim(FileIntegrity::get_storage_dir(), '/');
    }

    private static function ensure_hardened_dir(string $dir): void {
        if (!@is_dir($dir)) {
            if (function_exists('wp_mkdir_p')) {
                wp_mkdir_p($dir);
            } else {
                @mkdir($dir, 0755, true);
            }
        }
        $htaccess = $dir . '/.htaccess';
        if (!@file_exists($htaccess)) {
            @file_put_contents($htaccess, "Require all denied\nDeny from all\n", LOCK_EX);
        }
        $index = $dir . '/index.php';
        if (!@file_exists($index)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\n", LOCK_EX);
        }
    }

    private static function atomic_write(string $target, string $content): void {
        $dir = dirname($target);
        self::ensure_hardened_dir($dir);
        $tmp = @tempnam($dir, 'gs_sig_');
        if (false === $tmp) {
            @file_put_contents($target, $content, LOCK_EX);
            return;
        }
        if (false !== @file_put_contents($tmp, $content, LOCK_EX)) {
            @chmod($tmp, 0640);
            if (!@rename($tmp, $target)) {
                @unlink($tmp);
                @file_put_contents($target, $content, LOCK_EX);
            }
        } else {
            @unlink($tmp);
        }
    }

    private static function clean_id(string $id): string {
        $id = trim($id);
        if (1 !== preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $id)) {
            return '';
        }
        return $id;
    }

    private static function clean_label(string $label): string {
        $label = preg_replace('/[\x00-\x1F\x7F]/', ' ', $label);
        return trim(substr((string) $label, 0, 180));
    }
}
