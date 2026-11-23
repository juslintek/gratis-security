<?php
/**
 * Plugin Name: Gratis Security
 * Plugin URI: https://github.com/juslintek/gratis-security
 * Description: Web application firewall, login rate limiting, security headers, file-integrity monitoring, malware scanning, and TOTP 2FA.
 * Version: 2.0.0
 * Requires at least: 6.4
 * Requires PHP: 8.1
 * Author: Linas Jusys
 * Author URI: https://github.com/juslintek
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: gratis-security
 *
 * @package Gratis\Security
 */

defined('ABSPATH') || exit;

define('GRATIS_SECURITY_VERSION', '2.0.0');
define('GRATIS_SECURITY_FILE', __FILE__);
define('GRATIS_SECURITY_DIR', plugin_dir_path(__FILE__));
define('GRATIS_SECURITY_URL', plugin_dir_url(__FILE__));

require_once __DIR__ . '/autoload.php';

// Firewall runs as early as possible.
add_action('init', [\Gratis\Security\WAF::class, 'check'], -9999);

// 404 probe and scanner flood detection.
add_action('template_redirect', [\Gratis\Security\RequestGuard::class, 'track_404']);

// Security response headers on the front end.
add_action('send_headers', [\Gratis\Security\Headers::class, 'send'], 100);

// Admin settings page under the Settings menu.
add_action('admin_menu', [\Gratis\Security\Settings::class, 'register_menu']);
add_action('admin_init', [\Gratis\Security\Settings::class, 'register_settings']);
add_action('init', [\Gratis\Security\Settings::class, 'register_ajax']);

// File Integrity Monitoring, Malware Scanning & Signature Feed cron schedules.
// phpcs:ignore WordPress.WP.CronInterval.CronSchedulesInterval -- Real-time FIM event log tailing runs every 5 minutes.
add_filter('cron_schedules', static function (array $schedules): array {
    $schedules['gratis_five_minutes'] = [
        'interval' => 300,
        'display'  => did_action('init') ? __('Every 5 Minutes', 'gratis-security') : 'Every 5 Minutes',
    ];
    return $schedules;
});

add_action(\Gratis\Security\FileIntegrity::CRON_HOOK, [\Gratis\Security\FileIntegrity::class, 'cron_scan']);
add_action(\Gratis\Security\EventMonitor::CRON_HOOK, [\Gratis\Security\EventMonitor::class, 'trail']);
add_action(\Gratis\Security\MalwareScanner::CRON_HOOK, [\Gratis\Security\MalwareScanner::class, 'cron_scan']);
add_action(\Gratis\Security\SignatureFeed::CRON_HOOK, [\Gratis\Security\SignatureFeed::class, 'update']);

add_action('init', static function (): void {
    if (
        \Gratis\Security\Settings::get_bool('integrity_enabled', true)
        && !wp_next_scheduled(\Gratis\Security\EventMonitor::CRON_HOOK)
    ) {
        wp_schedule_event(time() + 300, 'gratis_five_minutes', \Gratis\Security\EventMonitor::CRON_HOOK);
    }

    if (
        \Gratis\Security\Settings::get_bool('malware_auto_scan', true)
        && !wp_next_scheduled(\Gratis\Security\MalwareScanner::CRON_HOOK)
    ) {
        wp_schedule_event(time() + 600, 'daily', \Gratis\Security\MalwareScanner::CRON_HOOK);
    }

    if (
        \Gratis\Security\Settings::get_bool('signature_auto_update', true)
        && !wp_next_scheduled(\Gratis\Security\SignatureFeed::CRON_HOOK)
    ) {
        wp_schedule_event(time() + 180, 'daily', \Gratis\Security\SignatureFeed::CRON_HOOK);
    }
});

add_action('plugins_loaded', function () {
    \Gratis\Security\LoginProtection::init();
    \Gratis\Security\TwoFactor::init();

    if (defined('WP_CLI') && WP_CLI) {
        \WP_CLI::add_command('gratis-security', \Gratis\Security\CLI\SecurityCommand::class);
    }
});
