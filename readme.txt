=== Gratis Security ===
Contributors: juslintek
Tags: security, firewall, two factor, malware, login security
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 2.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Firewall, login rate limiting, security headers, file integrity, and TOTP two-factor.

== Description ==

Firewall, login rate limiting, security headers, file integrity, and TOTP two-factor.

Part of the Gratis suite — a collection of free, no-upsell WordPress plugins.

**Features:**

* Web application firewall (SQLi/XSS/path-traversal)
* Login rate limiting and lockout
* Security response headers (with optional CSP and HSTS)
* File-integrity monitoring and malware scanning
* TOTP two-factor authentication

**Philosophy:**

Everything is free. No "Pro" version, no locked features, no nag screens. Optional managed cloud services may be offered separately to cover infrastructure costs.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Configure it from its settings screen in the WordPress admin.

== Frequently Asked Questions ==

= Is this plugin really free? =

Yes. Everything is free — no "Pro" version, no locked features, and no nag screens. Optional managed cloud services may be offered separately to cover infrastructure costs.

= Does this plugin make external HTTP requests? =

Only when you trigger WordPress core file-integrity checks (against official WordPress.org checksums) or enable optional threat signature feeds. It never phones home or sends analytics.

= Where do I get support? =

Open an issue on the plugin's GitHub repository.

== Third-Party Services ==

This plugin makes outbound requests only for optional security verification features:

= WordPress.org Core Checksums and Source Diff =

When you run a File Integrity scan or view a core file diff, the plugin queries the official WordPress.org Checksums API (`https://api.wordpress.org/core/checksums/1.0/`) and WordPress Core SVN (`https://core.svn.wordpress.org/`) to compare local core files against official releases.

* [WordPress.org Privacy Policy](https://wordpress.org/about/privacy/)

= Optional Threat Signature Feeds =

If you manually configure custom signature feed URLs in the Feeds tab, the plugin fetches those user-supplied URLs on demand or via scheduled refresh. No third-party feed is contacted unless you enable it.

== Changelog ==

= 2.0.0 =
* Full WAF, malware scanner, file-integrity monitor, security headers, server hardening wizard, and TOTP two-factor authentication release.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 2.0.0 =
Full security suite release with TOTP 2FA, WAF, and file integrity monitoring.
