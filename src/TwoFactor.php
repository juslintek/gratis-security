<?php declare(strict_types=1);
namespace Gratis\Security;

/** TOTP-based 2FA for admin accounts. */
final class TwoFactor {

    public static function init(): void {
        if (!get_option('gratis_security_2fa_enabled')) return;
        add_action('wp_login', [__CLASS__, 'checkRequired'], 10, 2);
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
        $timeSlice = floor(time() / 30);
        // Check current and adjacent time slices (±1)
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

    public static function checkRequired(string $username, \WP_User $user): void {
        if (!user_can($user, 'manage_options')) return;
        $secret = get_user_meta($user->ID, '_gratis_2fa_secret', true);
        if (!$secret) return; // 2FA not set up for this user
        // In a full implementation, this would redirect to a 2FA verification page
    }
}
