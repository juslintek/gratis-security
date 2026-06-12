<?php declare(strict_types=1);

namespace Gratis\Security;

defined('ABSPATH') || exit;

/**
 * File integrity monitoring for WordPress core. Captures a baseline of MD5
 * hashes for files under wp-admin/ and wp-includes/, then reports files that
 * have changed or gone missing relative to that baseline.
 */
final class FileIntegrity {

    /** Option storing the baseline hashes + timestamp. */
    public const OPTION = 'gratis_security_integrity';

    /** Core directories to monitor, relative to ABSPATH. */
    private const CORE_DIRS = ['wp-admin', 'wp-includes'];

    /**
     * Build (or rebuild) the integrity baseline. Returns the file count stored.
     */
    public static function build_baseline(): int {
        $hashes = self::hash_core();

        update_option(
            self::OPTION,
            [
                'built_at' => gmdate('c'),
                'hashes'   => $hashes,
            ],
            false
        );

        return count($hashes);
    }

    /**
     * Compare the current core files against the saved baseline.
     *
     * @return array{changed:array<int,string>,missing:array<int,string>,checked:int}
     */
    public static function scan(): array {
        $stored = get_option(self::OPTION, []);
        $baseline = is_array($stored) && isset($stored['hashes']) && is_array($stored['hashes'])
            ? $stored['hashes']
            : [];

        $result = ['changed' => [], 'missing' => [], 'checked' => 0];
        if (empty($baseline)) {
            return $result;
        }

        $current = self::hash_core();
        $result['checked'] = count($baseline);

        foreach ($baseline as $relative => $hash) {
            if (!isset($current[$relative])) {
                $result['missing'][] = (string) $relative;
                continue;
            }
            if (!hash_equals((string) $hash, (string) $current[$relative])) {
                $result['changed'][] = (string) $relative;
            }
        }

        return $result;
    }

    /**
     * Hash every PHP file under the monitored core directories.
     *
     * @return array<string,string> Map of relative path => md5 hash.
     */
    private static function hash_core(): array {
        $hashes = [];

        foreach (self::CORE_DIRS as $dir) {
            $root = ABSPATH . $dir;
            if (!is_dir($root)) {
                continue;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if (!$file->isFile() || 'php' !== strtolower($file->getExtension())) {
                    continue;
                }
                $path = $file->getPathname();
                $hash = md5_file($path);
                if (false === $hash) {
                    continue;
                }
                $relative          = str_replace(ABSPATH, '', $path);
                $hashes[$relative] = $hash;
            }
        }

        return $hashes;
    }
}
