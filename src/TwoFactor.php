<?php declare(strict_types=1);
namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * TOTP-based two-factor authentication for administrator accounts.
 *
 * Enforcement is a two-step login interstitial: WordPress validates the
 * password as usual (the primary factor), then — before the auth cookie is
 * issued — this class interrupts the login on the {@see 'authenticate'} chain
 * and asks for a TOTP code. The cookie is only set once the code verifies.
 * Users without a confirmed secret are never blocked.
 */
final class TwoFactor {

    /** User meta key holding the confirmed (active) TOTP secret. */
    public const META_SECRET = '_gratis_2fa_secret';

    /** User meta key holding the not-yet-confirmed enrolment secret. */
    private const META_PENDING = '_gratis_2fa_pending_secret';

    /** Transient key prefix for single-use, pre-auth login nonces. */
    private const NONCE_PREFIX = 'gratis_2fa_login_';

    /** Lifetime of a pending-login nonce, in seconds (5 minutes). */
    private const NONCE_TTL = 300;

    /**
     * Wire up enforcement and enrolment when 2FA is enabled in settings.
     */
    public static function init(): void {
        if (!Settings::get_bool('twofa_enabled')) {
            return;
        }

        // Step 1: interrupt the interactive login after the password is valid.
        add_filter('authenticate', [__CLASS__, 'maybeIntercept'], 50, 1);
        // Step 2: handle the TOTP code submission (wp-login.php?action=gratis_2fa).
        add_action('login_form_gratis_2fa', [__CLASS__, 'validateLogin']);

        // Per-user self-service enrolment on the profile screen.
        add_action('show_user_profile', [__CLASS__, 'renderProfileSection']);
        add_action('edit_user_profile', [__CLASS__, 'renderProfileSection']);
        add_action('personal_options_update', [__CLASS__, 'saveProfileSection']);
        add_action('edit_user_profile_update', [__CLASS__, 'saveProfileSection']);
    }

    /** Generate a TOTP secret for a user. */
    public static function generateSecret(): string {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < 16; $i++) $secret .= $chars[random_int(0, 31)];
        return $secret;
    }

    /** Verify a TOTP code against a secret. */
    public static function verify(string $secret, string $code): bool {
        if ('' === $secret || '' === $code) {
            return false;
        }
        $timeSlice = (int) floor(time() / 30);
        // Check current and adjacent time slices (±1).
        for ($i = -1; $i <= 1; $i++) {
            $expected = self::generateCode($secret, $timeSlice + $i);
            if (hash_equals($expected, $code)) return true;
        }
        return false;
    }

    private static function generateCode(string $secret, int $timeSlice): string {
        $key = self::base32Decode($secret);
        $time = pack('N*', 0, $timeSlice);
        $hash = hash_hmac('sha1', $time, $key, true);
        $offset = ord($hash[19]) & 0x0F;
        $code = (unpack('N', substr($hash, $offset, 4))[1] & 0x7FFFFFFF) % 1000000;
        return str_pad((string) $code, 6, '0', STR_PAD_LEFT);
    }

    private static function base32Decode(string $input): string {
        $map      = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $buffer   = 0;
        $bitsLeft = 0;
        $output   = '';
        $length   = strlen($input);
        for ($i = 0; $i < $length; $i++) {
            $val = strpos($map, $input[$i]);
            if (false === $val) {
                continue;
            }
            $buffer    = ($buffer << 5) | $val;
            $bitsLeft += 5;
            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $output   .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }
        return $output;
    }

    /**
     * Persist a confirmed secret for a user (admin/CLI tooling entry point).
     */
    public static function setSecret(int $user_id, string $secret): void {
        update_user_meta($user_id, self::META_SECRET, $secret);
        delete_user_meta($user_id, self::META_PENDING);
    }

    /**
     * Remove all 2FA data for a user (disable).
     */
    public static function clearForUser(int $user_id): void {
        delete_user_meta($user_id, self::META_SECRET);
        delete_user_meta($user_id, self::META_PENDING);
    }

    /**
     * Build an otpauth:// provisioning URI for an authenticator app.
     */
    public static function provisioningUri(\WP_User $user, string $secret): string {
        $issuer = trim(wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES));
        if ('' === $issuer) {
            $issuer = 'WordPress';
        }
        $label = $issuer . ':' . $user->user_login;
        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
            rawurlencode($label),
            rawurlencode($secret),
            rawurlencode($issuer)
        );
    }

    /**
     * Interrupt the interactive login once the password factor has passed.
     *
     * @param \WP_User|\WP_Error|null $user Result so far in the authenticate chain.
     * @return \WP_User|\WP_Error|null Unchanged unless a second factor is required.
     */
    public static function maybeIntercept($user) {
        // Password not (yet) valid, or another factor failed: leave it alone.
        if (!$user instanceof \WP_User) {
            return $user;
        }
        // Only the interactive wp-login.php flow sets login_init. This excludes
        // XML-RPC, REST, application passwords and programmatic sign-ins, which
        // cannot render an interstitial.
        if (!did_action('login_init')) {
            return $user;
        }
        if (!self::userRequires2fa($user)) {
            return $user; // No confirmed secret → never lock the user out.
        }

        self::showForm($user);
        exit;
    }

    /**
     * Handle the TOTP code submitted by the interstitial and grant the session.
     */
    public static function validateLogin(): void {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Pre-auth login step; the request is authenticated below by a single-use transient login nonce (hash_equals), not a session-bound WP nonce (none exists pre-login).
        $user_id = isset($_POST['gratis_2fa_user']) ? absint(wp_unslash($_POST['gratis_2fa_user'])) : 0;
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- This is the login nonce value, verified on the next lines via self::verifyLoginNonce().
        $nonce = isset($_POST['gratis_2fa_nonce']) ? sanitize_text_field(wp_unslash($_POST['gratis_2fa_nonce'])) : '';

        $user = $user_id > 0 ? get_user_by('id', $user_id) : false;
        if (!$user instanceof \WP_User || !self::verifyLoginNonce($user_id, $nonce)) {
            // Expired or forged second step: restart the login.
            wp_safe_redirect(wp_login_url());
            exit;
        }

        // Login nonce verified above; the remaining fields belong to this request.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- login nonce verified above.
        $raw_code = isset($_POST['gratis_2fa_code']) ? sanitize_text_field(wp_unslash($_POST['gratis_2fa_code'])) : '';
        $code     = (string) preg_replace('/\D/', '', $raw_code);

        $secret = (string) get_user_meta($user->ID, self::META_SECRET, true);
        if ('' === $secret || !self::verify($secret, $code)) {
            // Re-issue a fresh nonce and show the form again with an error.
            self::showForm($user, __('Invalid authentication code. Please try again.', 'gratis-security'));
            exit;
        }

        // Success: consume the nonce and grant the session.
        self::deleteLoginNonce($user->ID);

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- login nonce verified above.
        $remember = !empty($_POST['rememberme']);
        wp_set_auth_cookie($user->ID, $remember);
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress login lifecycle action.
        do_action('wp_login', $user->user_login, $user);

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- login nonce verified above.
        $requested   = isset($_POST['redirect_to']) ? esc_url_raw(wp_unslash($_POST['redirect_to'])) : '';
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress login redirect filter.
        $redirect_to = apply_filters('login_redirect', '' !== $requested ? $requested : admin_url(), $requested, $user);
        wp_safe_redirect('' !== (string) $redirect_to ? (string) $redirect_to : admin_url());
        exit;
    }

    /**
     * Render the second-factor prompt on the login screen.
     */
    private static function showForm(\WP_User $user, string $error = ''): void {
        $nonce = self::createLoginNonce($user->ID);

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Login screen; the password factor was already validated by core before this interstitial. The value is re-validated by wp_safe_redirect() on submit.
        $redirect_to = isset($_REQUEST['redirect_to']) ? esc_url_raw(wp_unslash($_REQUEST['redirect_to'])) : admin_url();
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- See above; read only as a boolean.
        $remember = !empty($_REQUEST['rememberme']);

        $wp_error = new \WP_Error();
        if ('' !== $error) {
            $wp_error->add('gratis_2fa_error', $error);
        }

        login_header(esc_html__('Two-Factor Verification', 'gratis-security'), '', $wp_error);

        echo '<form name="gratis2faform" id="gratis2faform" method="post" action="' . esc_url(site_url('wp-login.php?action=gratis_2fa', 'login_post')) . '">';
        echo '<p><label for="gratis_2fa_code">' . esc_html__('Authentication code', 'gratis-security') . '<br />';
        echo '<input type="text" name="gratis_2fa_code" id="gratis_2fa_code" class="input" value="" size="20" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]*" autofocus="autofocus" /></label></p>';
        echo '<input type="hidden" name="gratis_2fa_user" value="' . esc_attr((string) $user->ID) . '" />';
        echo '<input type="hidden" name="gratis_2fa_nonce" value="' . esc_attr($nonce) . '" />';
        echo '<input type="hidden" name="redirect_to" value="' . esc_url($redirect_to) . '" />';
        if ($remember) {
            echo '<input type="hidden" name="rememberme" value="1" />';
        }
        echo '<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="' . esc_attr__('Verify', 'gratis-security') . '" /></p>';
        echo '</form>';

        login_footer('gratis_2fa_code');
    }

    /**
     * Render the per-user enrolment section on the profile screen.
     */
    public static function renderProfileSection(\WP_User $user): void {
        // Self-service only: you enrol 2FA on your own admin account (you must be
        // able to scan the secret into your own authenticator).
        if (get_current_user_id() !== $user->ID || !user_can($user, 'manage_options')) {
            return;
        }

        echo '<h2>' . esc_html__('Two-Factor Authentication', 'gratis-security') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';

        if (self::userHasSecret($user->ID)) {
            echo '<tr><th scope="row">' . esc_html__('Status', 'gratis-security') . '</th><td>';
            echo '<p><strong>' . esc_html__('Enabled — an authentication code is required when you log in.', 'gratis-security') . '</strong></p>';
            wp_nonce_field('gratis_2fa_profile', 'gratis_2fa_nonce');
            echo '<label><input type="checkbox" name="gratis_2fa_disable" value="1" /> ' . esc_html__('Disable two-factor authentication for my account', 'gratis-security') . '</label>';
            echo '</td></tr>';
        } else {
            $secret = self::pendingSecret($user->ID);
            $uri    = self::provisioningUri($user, $secret);
            echo '<tr><th scope="row">' . esc_html__('Set up', 'gratis-security') . '</th><td>';
            echo '<p>' . esc_html__('Add this key to an authenticator app (Google Authenticator, Aegis, 1Password, …), then enter the current 6-digit code and save your profile to activate.', 'gratis-security') . '</p>';
            echo '<p><strong>' . esc_html__('Manual key:', 'gratis-security') . '</strong> <code>' . esc_html($secret) . '</code></p>';
            echo '<p><strong>' . esc_html__('Setup URI:', 'gratis-security') . '</strong> <code>' . esc_html($uri) . '</code></p>';
            wp_nonce_field('gratis_2fa_profile', 'gratis_2fa_nonce');
            echo '<p><label for="gratis_2fa_activate_code">' . esc_html__('Verification code', 'gratis-security') . '</label><br />';
            echo '<input type="text" id="gratis_2fa_activate_code" name="gratis_2fa_activate_code" value="" class="regular-text" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]*" /></p>';
            echo '</td></tr>';
        }

        echo '</tbody></table>';
    }

    /**
     * Persist enrolment / disable choices from the profile screen.
     */
    public static function saveProfileSection(int $user_id): void {
        if (get_current_user_id() !== $user_id || !current_user_can('manage_options') || !user_can($user_id, 'manage_options')) {
            return;
        }
        if (!isset($_POST['gratis_2fa_nonce'])
            || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['gratis_2fa_nonce'])), 'gratis_2fa_profile')
        ) {
            return;
        }

        // Disable path.
        if (!empty($_POST['gratis_2fa_disable'])) {
            self::clearForUser($user_id);
            return;
        }

        // Activation path: confirm a current code against the pending secret.
        $raw_code = isset($_POST['gratis_2fa_activate_code']) ? sanitize_text_field(wp_unslash($_POST['gratis_2fa_activate_code'])) : '';
        $code     = (string) preg_replace('/\D/', '', $raw_code);
        if ('' === $code) {
            return; // Nothing to activate.
        }

        $pending = (string) get_user_meta($user_id, self::META_PENDING, true);
        if ('' !== $pending && self::verify($pending, $code)) {
            self::setSecret($user_id, $pending);
        }
        // On a wrong code the pending secret is left in place so the user can
        // retry with the same key; the section still shows "Set up".
    }

    /**
     * Whether 2FA must be enforced for this user at login.
     */
    private static function userRequires2fa(\WP_User $user): bool {
        if (!user_can($user, 'manage_options')) {
            return false;
        }
        return self::userHasSecret($user->ID);
    }

    /**
     * Whether the user has a confirmed (active) secret.
     */
    private static function userHasSecret(int $user_id): bool {
        $secret = get_user_meta($user_id, self::META_SECRET, true);
        return is_string($secret) && '' !== $secret;
    }

    /**
     * Return the user's pending enrolment secret, generating one on first view.
     */
    private static function pendingSecret(int $user_id): string {
        $pending = get_user_meta($user_id, self::META_PENDING, true);
        if (!is_string($pending) || '' === $pending) {
            $pending = self::generateSecret();
            update_user_meta($user_id, self::META_PENDING, $pending);
        }
        return $pending;
    }

    /**
     * Create a single-use, short-lived login nonce for the pending second step.
     */
    private static function createLoginNonce(int $user_id): string {
        $nonce = wp_generate_password(24, false, false);
        set_transient(self::NONCE_PREFIX . $user_id, wp_hash($nonce), self::NONCE_TTL);
        return $nonce;
    }

    /**
     * Verify a login nonce against the stored hash in constant time.
     */
    private static function verifyLoginNonce(int $user_id, string $nonce): bool {
        if ($user_id <= 0 || '' === $nonce) {
            return false;
        }
        $stored = get_transient(self::NONCE_PREFIX . $user_id);
        return is_string($stored) && '' !== $stored && hash_equals($stored, wp_hash($nonce));
    }

    /**
     * Consume a login nonce.
     */
    private static function deleteLoginNonce(int $user_id): void {
        delete_transient(self::NONCE_PREFIX . $user_id);
    }
}
