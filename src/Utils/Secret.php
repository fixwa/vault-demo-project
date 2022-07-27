<?php

namespace Pablo\Vault2\Utils;

use Exception;

class Secret
{
    protected const STORAGE_PREFIX = 'secret.';
    private const SECRET_KEY = 'imarandomkey';

    public static function read(string $key): ?string
    {
        $token = Settings::read(static::STORAGE_PREFIX . $key);
        if (empty($token)) {
            return null;
        }
        $value = unserialize(SecureToken::decode($token, self::SECRET_KEY));
        if (is_array($value) || is_object($value)) {
            $value = json_encode($value);
        }
        return $value;
    }

    public static function readAsJson(string $key, $default = null): ?array
    {
        $json = static::read($key);
        if ($json === null || $json === '') {
            return $default;
        }

        $value = json_decode($json, true);
        $error = json_last_error();

        if ($error !== JSON_ERROR_NONE) {
            throw new Exception(json_last_error_msg(), $error);
        }

        return $value;
    }

    public static function write(string $key, $value)
    {
        $key = static::STORAGE_PREFIX . $key;
        $token = SecureToken::encode(serialize($value), self::SECRET_KEY);
        return Settings::write($key, $token);
    }
}
