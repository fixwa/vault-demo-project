<?php
declare(strict_types=1);

namespace Pablo\Vault2\Utils;

use Http\Client\Curl\Client;
use VaultPHP\Authentication\Provider\Token;
use VaultPHP\Exceptions\InvalidDataException;
use VaultPHP\Exceptions\InvalidRouteException;
use VaultPHP\Exceptions\VaultException;
use VaultPHP\SecretEngines\Engines\Transit\EncryptionType;
use VaultPHP\SecretEngines\Engines\Transit\Request\CreateKeyRequest;
use VaultPHP\SecretEngines\Engines\Transit\Request\DecryptData\DecryptDataRequest;
use VaultPHP\SecretEngines\Engines\Transit\Request\EncryptData\EncryptDataRequest;
use VaultPHP\SecretEngines\Engines\Transit\Transit;
use VaultPHP\VaultClient;


class Vault
{
    private const TOKEN = 'the-dev-key';
    private const VAULT_API_HOST = 'http://127.0.0.1:8200';

    private VaultClient $vaultClient;
    private Transit $api;

    public function __construct()
    {
        $httpClient = new Client(null, null, [
            CURLOPT_VERBOSE => '0',
        ]);

        $auth = new Token('the-dev-key');

        $this->vaultClient = new VaultClient(
            $httpClient,
            $auth,
            self::VAULT_API_HOST
        );

        $this->api = new Transit($this->vaultClient);
    }

    /**
     * @throws InvalidRouteException
     * @throws VaultException
     * @throws InvalidDataException
     */
    public function saveSecret(string $key, string $value): string
    {
        $keyRequest = new CreateKeyRequest($key);
        $keyRequest->setType(EncryptionType::CHA_CHA_20_POLY_1305);
        $this->api->createKey($keyRequest);

        $encryptExample = new EncryptDataRequest($key, $value);
        return $this->api->encryptData($encryptExample)->getCiphertext();
    }

    public function decryptSecret(string $key, string $cipherText): string
    {
        $decryptExample = new DecryptDataRequest($key, $cipherText);
        $decryptResponse = $this->api->decryptData($decryptExample);
        return $decryptResponse->getPlaintext();

    }
}
