<?php

namespace Pablo\Vault2\Utils;

use Exception;

class SecureToken
{
    public const SECURE_TOKEN = 0x00;
    public const QUICK_TOKEN = 0x10;
    public const COMPACT_TOKEN = 0x20;
    public const JSON_PAYLOAD = 0x40;
    protected const SELECTOR_MASK = 0x0f;
    protected const TOKEN_TYPE_MASK = 0x30;
    protected const AES_BLOCK_SIZE = 16;
    protected const AES128_KEY_LENGTH = 16;
    protected const AES256_KEY_LENGTH = 32;
    protected const SHA1_LENGTH = 20;
    protected const SHA256_LENGTH = 32;
    protected const SHA512_LENGTH = 64;
    protected const OPERATION_ENCRYPT = 'encrypt';
    protected const OPERATION_DECRYPT = 'decrypt';
    protected static string $tokenRegex = '/^([-_a-zA-Z0-9]+)\.([-_a-zA-Z0-9]+)~$/';

    /**
     * @throws Exception
     */
    public static function aes($operation, $data, $key): bool|string|null
    {
        switch ($operation) {
            case self::OPERATION_ENCRYPT:
                $iv = empty($key->iv) ? self::keygen(self::AES_BLOCK_SIZE) : $key->iv;
                if (!is_string($iv) || strlen($iv) != self::AES_BLOCK_SIZE) {
                    return null;
                }
                $bits = strlen($key->encrypt) << 3;
                $crypt = openssl_encrypt($data, "AES-$bits-CBC", $key->encrypt, OPENSSL_RAW_DATA, $iv);
                return $iv . $crypt;
            case self::OPERATION_DECRYPT:
                $iv = substr($data, 0, self::AES_BLOCK_SIZE);
                $bits = strlen($key->encrypt) << 3;
                $ctext = substr($data, self::AES_BLOCK_SIZE);
                $ptext = openssl_decrypt($ctext, "AES-$bits-CBC", $key->encrypt, OPENSSL_RAW_DATA, $iv);
                return $ptext;
            default:
                return null;
        }
    }

    public static function encode($data, $key, $flags = 0): string
    {
        $key = self::setupKey($key, $flags);
        if (!$key || !is_int($flags) || $flags > 127 || $flags < 0) {
            return "";
        }
        if (!is_string($data)) {
            $data = @json_encode($data);
            if ($data === null) {
                return "";
            }
            $flags |= self::JSON_PAYLOAD;
        }
        $data .= chr($flags);
        $header = chr($flags) . self::sign($data, $key, $flags);
        $payload = self::aes('encrypt', $data, $key);
        return self::base64urlEncode($header) . '.' . self::base64urlEncode($payload) . '~';
    }

    /**
     * @throws Exception
     */
    public static function decode(string $token, $key)
    {
        $t = self::parse($token);
        if (!$t) {
            return null;
        }
        $key = self::setupKey($key, $t->flags);
        $ptext = self::aes('decrypt', $t->payload, $key);
        $plen = strlen($ptext);
        if ($ptext === null || ord($ptext[$plen - 1]) !== $t->flags) {
            return null;
        }
        $payload = substr($ptext, 0, $plen - 1);
        if ($t->flags & self::JSON_PAYLOAD) {
            $payload = @json_decode($payload);
        }

        return $payload;
    }

    /**
     * @throws Exception
     */
    public static function keygen(int $length = 0, int $flags = 0): ?string
    {
        if (!is_int($length) || $length < 0 || $length > 1024) {
            return null;
        }
        if (!$length) {
            switch ($flags & self::TOKEN_TYPE_MASK) {
                case self::SECURE_TOKEN:
                    $length = self::AES256_KEY_LENGTH;
                    break;
                case self::QUICK_TOKEN:
                case self::COMPACT_TOKEN:
                    $length = self::AES128_KEY_LENGTH;
                    break;
                default:
                    return null;
            }
        }

        return random_bytes($length);
    }

    protected static function base64urlEncode($input): array|string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    protected static function base64urlDecode($input): bool|string
    {
        return base64_decode(str_pad(strtr($input, '-_', '+/'), (strlen($input) + 3) & ~3, '='));
    }

    protected static function hashLength($algo): int
    {
        switch (strtolower(str_replace('-', '', $algo))) {
            case 'sha1':
                return self::SHA1_LENGTH;
            case 'sha256':
                return self::SHA256_LENGTH;
            case 'sha512':
                return self::SHA512_LENGTH;
        }
        return strlen(hash($algo, "test", true));
    }

    protected static function hash($algo, $data): bool|string
    {
        return hash($algo, $data, true);
    }

    protected static function hmac($algo, $data, $key): bool|string
    {
        return hash_hmac($algo, $data, $key, true);
    }

    protected static function kdf2($algo, $length, $key, $context = ""): string
    {
        $hashLength = self::hashLength($algo);
        $reps = ceil($length / $hashLength);
        $out = "";
        for ($i = 1; $i <= $reps; $i++) {
            $out .= self::hash($algo, $key . pack('N', $i) . $context);
        }
        return substr($out, 0, $length);
    }

    protected static function hkdf($algo, $length, $sourceKey, $context = "", $salt = null): string
    {
        // see https://tools.ietf.org/html/rfc5869
        $hashLength = self::hashLength($algo);
        if (!$salt) {
            $salt = str_repeat("\0", $hashLength);
        }
        $prk = self::hmac($algo, $salt, $sourceKey);
        $reps = ceil($length / $hashLength);
        $tn = "";
        $out = "";
        for ($i = 1; $i <= $reps; $i++) {
            $tn = self::hmac($algo, $tn . $context . chr($i), $prk);
            $out .= $tn;
        }
        return substr($out, 0, $length);
    }

    protected static function parse($data): ?object
    {
        if (!$data || !is_string($data) || !preg_match(self::$tokenRegex, $data, $parts)) {
            return null;
        }
        $header = self::base64urlDecode($parts[1]);
        $payload = self::base64urlDecode($parts[2]);
        return (object)[
            'flags' => ord($header[0]),
            'sig' => substr($header, 1),
            'payload' => $payload,
        ];
    }

    protected static function setupKey($key, $flags): ?object
    {
        if (is_array($key) && isset($key[$flags & self::SELECTOR_MASK])) {
            $key = $key[$flags & self::SELECTOR_MASK];
        }
        if (is_array($key)) {
            $key = (object)$key;
        }
        $salt = null;
        $iv = null;
        if (is_object($key)) {
            if (!isset($key->key) || !is_string($key->key)) {
                return null;
            }
            if (isset($key->salt)) {
                if (!is_string($key->salt) || strlen($key->salt) != self::AES256_KEY_LENGTH) {
                    return null;
                }
                $salt = $key->salt;
            }
            if (isset($key->iv)) {
                if (!is_string($key->iv) || strlen($key->iv) != self::AES_BLOCK_SIZE) {
                    return null;
                }
                $iv = $key->iv;
            }
            $key = $key->key;
        }
        if (!is_string($key)) {
            return null;
        }
        switch ($flags & self::TOKEN_TYPE_MASK) {
            case self::QUICK_TOKEN:
                return (object)[
                    'verify' => self::kdf2("sha256", self::SHA256_LENGTH, $key, "verify"),
                    'encrypt' => self::kdf2("sha256", self::AES128_KEY_LENGTH, $key, "encrypt"),
                    'iv' => $iv,
                ];
            case self::COMPACT_TOKEN:
                return (object)[
                    'verify' => self::kdf2("sha1", self::SHA1_LENGTH, $key, "verify"),
                    'encrypt' => self::kdf2("sha1", self::AES128_KEY_LENGTH, $key, "encrypt"),
                    'iv' => $iv,
                ];
            case self::SECURE_TOKEN:
                if ($salt === null) {
                    $salt = self::keygen(self::AES256_KEY_LENGTH);
                }
                return (object)[
                    'verify' => self::hkdf("sha512", self::SHA512_LENGTH, $key, "verify", $salt),
                    'encrypt' => self::hkdf("sha256", self::AES256_KEY_LENGTH, $key, "encrypt"),
                    'salt' => $salt,
                    'iv' => $iv,
                ];
        }
        return null;
    }

    protected static function sign($data, $key, $flags): bool|string|null
    {
        return match ($flags & self::TOKEN_TYPE_MASK) {
            self::SECURE_TOKEN => $key->salt . self::hmac('sha512', $data, $key->verify),
            self::QUICK_TOKEN => self::hmac('sha256', $data, $key->verify),
            self::COMPACT_TOKEN => substr(self::hmac('sha1', $data, $key->verify), 0, 10),
            default => null,
        };
    }
}
