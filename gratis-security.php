<?php
/**
 * Plugin Name: Gratis Security
 * Description: WAF rules + malware file scanner + 2FA login. Replaces Wordfence ($119/yr).
 * Version: 1.0.0
 * Requires PHP: 8.1
 * Author: Linas Jusys
 * License: GPL-2.0-or-later
 */
defined('ABSPATH') || exit;
require_once __DIR__ . '/autoload.php';
add_action('init', [\Gratis\Security\WAF::class, 'check'], -9999);
add_action('plugins_loaded', function () {
    \Gratis\Security\TwoFactor::init();
    if (defined('WP_CLI') && WP_CLI) \WP_CLI::add_command('gratis-security', \Gratis\Security\CLI\SecurityCommand::class);
});
