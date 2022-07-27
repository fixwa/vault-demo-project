<?php
declare(strict_types=1);

namespace Pablo\Vault2;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\MessageFormatter;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\Utils;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Pablo\Vault2\Utils\Secret;
use Pablo\Vault2\Utils\Settings;
use Pablo\Vault2\Utils\Vault;


class RandomApiDemo
{
    private Logger $logger;
    private GuzzleClient $httpClient;
    private Vault $vaultClient;

    public function __construct()
    {
        $this->logger = new Logger('demo');
        $this->logger->pushHandler(new StreamHandler('php://stdout'));
        $this->logger->debug('🌈 STARTING ...');

        // prepare Guzzle
        $stack = new HandlerStack();
        $stack->setHandler(Utils::chooseHandler());
        $stack->push(Middleware::mapRequest(function (Request $request) {
            // $remoteApiAuthorizationToken = $this->getClientAccessTokenFromDatabase();
            $remoteApiAuthorizationToken = $this->getClientAccessTokenFromVault();
            return $request->withHeader('Authorization', 'Bearer ' . $remoteApiAuthorizationToken);
        }));
        //$stack->push(Middleware::log($logger, new MessageFormatter('RESPONSE: {code} - {res_body}')));
        $stack->push(Middleware::log($this->logger, new MessageFormatter('🐌 REQUEST: {method} {uri} HEADERS: {req_headers} BODY: {req_body}')));

        $this->httpClient = new GuzzleClient([
            'base_uri' => 'https://app.risebuildings.com',
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'handler' => $stack,
        ]);

        $this->vaultClient = new Vault();
    }

    public function callRemoteApi()
    {
        $resp = $this->httpClient->get('/v2/users?property_id=5a7cad2f5e2341053097272d'); // Request an external API (RISE) to fetch Residents...

        $resp->getBody()->rewind();
        $contents = $resp->getBody()->getContents();
        if (!empty($contents)) {
            $this->logger->debug("✅ Got response from remote API OK.");
            $this->logger->debug(json_encode($contents, JSON_PRETTY_PRINT));
        } else {
            $this->logger->error("❌ Failed while trying to request the remote API.");
        }
        $this->logger->debug('Done.');
    }

    private function getClientAccessTokenFromDatabase(): string
    {
        $storedToken = Secret::readAsJson('processor_rise_token_storage'); // get ENCRYPTED value from DB

        if (intval($storedToken['auth_token_expires_at']) > time()) {
            $this->logger->debug('Using stored token.');
            return $storedToken['auth_token'];
        }

        $client = new GuzzleClient();
        $loginResponse = $client->post('https://admin.riseliving.co/login', [
            RequestOptions::JSON => [
                'email' => 'MY_EMAIL__',                // Stored as PLAIN-TEXT in DATABASE
                'password' => 'MY_PASSWORD__',          // Stored as PLAIN-TEXT in DATABASE
            ],
            RequestOptions::HEADERS => [
                'Content-Type' => 'application/json',
            ],
        ]);
        $loginResponseArray = Utils::jsonDecode((string)$loginResponse->getBody(), true);

        $riseUserId = $loginResponseArray['data']['user_id'];
        $authToken = $loginResponseArray['data']['auth_token'];
        $refreshToken = $loginResponseArray['data']['refresh_token'];

        $refreshAccessTokenResponse = $client->post('https://app.risebuildings.com/api/refresh_bearer_token', [
            RequestOptions::JSON => [
                'user_id' => $riseUserId,
                'refresh_token' => $refreshToken,
            ],
            RequestOptions::HEADERS => [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $authToken,
            ],
        ]);

        $refreshAccessTokenResponseArray = Utils::jsonDecode((string)$refreshAccessTokenResponse->getBody(), true);
        Secret::write('processor_rise_token_storage', $refreshAccessTokenResponseArray); // STORE token as a "SECRET" + salt in the DATABASE encrypted with AES
        return $refreshAccessTokenResponseArray['auth_token'];
    }

    private function getClientAccessTokenFromVault()
    {
        $cipherText = Settings::read('cipher.vault_demo.obj');
        $plainText = $this->vaultClient->decryptSecret('VAULT_DEMO', $cipherText);
        $stringDecoded = base64_decode($plainText);
        $usableData = json_decode($stringDecoded, true);

        if (!empty($usableData)) {
            $this->logger->debug("🎉 Got values from Vault.");
        } else {
            $this->logger->error("⛈ Could not get values from Vault.");
        }

        //
        //
        //

        $client = new GuzzleClient();
        $loginResponse = $client->post('https://admin.riseliving.co/login', [
            RequestOptions::JSON => [
                'email' => $usableData['email'],       // encrypted content in Vault
                'password' => $usableData['password'],   // encrypted content in Vault
            ],
            RequestOptions::HEADERS => [
                'Content-Type' => 'application/json',
            ],
        ]);
        $loginResponseArray = Utils::jsonDecode((string)$loginResponse->getBody(), true);

        $riseUserId = $loginResponseArray['data']['user_id'];
        $authToken = $loginResponseArray['data']['auth_token'];
        $refreshToken = $loginResponseArray['data']['refresh_token'];

        $refreshAccessTokenResponse = $client->post('https://app.risebuildings.com/api/refresh_bearer_token', [
            RequestOptions::JSON => [
                'user_id' => $riseUserId,
                'refresh_token' => $refreshToken,
            ],
            RequestOptions::HEADERS => [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $authToken,
            ],
        ]);

        $authData = (string)$refreshAccessTokenResponse->getBody();

        $json = <<<JSON
{
    "email": {$usableData['email']},
    "password": {$usableData['password']},
    "authentication": $authData
}
JSON;

        $this->vaultClient->saveSecret('VAULT_DEMO', base64_encode($json)); // STORE the object in Vault (Encrypted)
        return json_decode($authData, true)['auth_token'];
    }
}



