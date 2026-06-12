<?php declare(strict_types=1);

defined('ABSPATH') || exit;

spl_autoload_register(function (string $className): void {
    $prefix = 'Gratis\\Security\\';
    if (strncmp($className, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = substr($className, strlen($prefix));
    $file     = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});
