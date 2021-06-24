<?php

namespace Vizir\KeycloakWebGuard\Services;

use Exception;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Vizir\KeycloakWebGuard\Auth\KeycloakAccessToken;

class KeycloakService
{
    /**
     * The Session key for token.
     */
    public const KEYCLOAK_SESSION = '_keycloak_token';

    /**
     * The Session key for state.
     */
    public const KEYCLOAK_SESSION_STATE = '_keycloak_state';

    /**
     * Keycloak URL.
     *
     * @var string
     */
    protected $baseUrl;

    /**
     * Keycloak Realm.
     *
     * @var string
     */
    protected $realm;

    /**
     * Keycloak Client ID.
     *
     * @var string
     */
    protected $clientId;

    /**
     * Keycloak Client Secret.
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Keycloak OpenId Configuration.
     *
     * @var array
     */
    protected $openid;

    /**
     * Keycloak OpenId Cache Configuration.
     *
     * @var array
     */
    protected $cacheOpenid;

    /**
     * CallbackUrl.
     *
     * @var array
     */
    protected $callbackUrl;

    /**
     * RedirectLogout.
     *
     * @var array
     */
    protected $redirectLogout;

    /**
     * The state for authorization request.
     *
     * @var string
     */
    protected $state;

    /**
     * The HTTP Client.
     *
     * @var ClientInterface
     */
    protected $httpClient;

    /**
     * The Constructor
     * You can extend this service setting protected variables before call
     * parent constructor to comunicate with Keycloak smoothly.
     */
    public function __construct(ClientInterface $client)
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim(Config::get('keycloak-web.base_url'), '/');
        }

        if (is_null($this->realm)) {
            $this->realm = Config::get('keycloak-web.realm');
        }

        if (is_null($this->clientId)) {
            $this->clientId = Config::get('keycloak-web.client_id');
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = Config::get('keycloak-web.client_secret');
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = Config::get('keycloak-web.cache_openid', false);
        }

        if (is_null($this->callbackUrl)) {
            $this->callbackUrl = route('keycloak.callback');
        }

        if (is_null($this->redirectLogout)) {
            $this->redirectLogout = Config::get('keycloak-web.redirect_logout');
        }

        $this->state = $this->generateRandomState();
        $this->httpClient = $client;
    }

    /**
     * Return the login URL.
     *
     * @see https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
     */
    public function getLoginUrl(): string
    {
        $url = $this->getOpenIdValue('authorization_endpoint');
        $params = [
            'scope' => 'openid',
            'response_type' => 'code',
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->callbackUrl,
            'state' => $this->getState(),
        ];

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the logout URL.
     */
    public function getLogoutUrl(): string
    {
        $url = $this->getOpenIdValue('end_session_endpoint');

        if (empty($this->redirectLogout)) {
            $this->redirectLogout = url('/');
        }

        $params = [
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->redirectLogout,
        ];

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the register URL.
     *
     * @see https://stackoverflow.com/questions/51514437/keycloak-direct-user-link-registration
     */
    public function getRegisterUrl(): string
    {
        $url = $this->getLoginUrl();

        return str_replace('/auth?', '/registrations?', $url);
    }

    /**
     * Get access token from Code.
     */
    public function getAccessToken(string $code): array
    {
        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'code' => $code,
            'client_id' => $this->getClientId(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];

        if (!empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if (200 === $response->getStatusCode()) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Refresh access token.
     *
     * @param mixed $credentials
     */
    public function refreshAccessToken($credentials): array
    {
        if (empty($credentials['refresh_token'])) {
            return [];
        }

        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'grant_type' => 'refresh_token',
            'refresh_token' => $credentials['refresh_token'],
            'redirect_uri' => $this->callbackUrl,
        ];

        if (!empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if (200 === $response->getStatusCode()) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Invalidate Refresh.
     */
    public function invalidateRefreshToken(string $refreshToken): bool
    {
        $url = $this->getOpenIdValue('end_session_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'refresh_token' => $refreshToken,
        ];

        if (!empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            return 204 === $response->getStatusCode();
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return false;
    }

    /**
     * Get access token from Code.
     */
    public function getUserProfile(array $credentials): array
    {
        $credentials = $this->refreshTokenIfNeeded($credentials);

        $user = [];

        try {
            // Validate JWT Token
            $token = new KeycloakAccessToken($credentials);

            if (empty($token->getAccessToken())) {
                throw new Exception('Access Token is invalid.');
            }

            $claims = [
                'aud' => $this->getClientId(),
                'iss' => $this->getOpenIdValue('issuer'),
            ];

            $token->validateIdToken($claims);

            // Get userinfo
            $url = $this->getOpenIdValue('userinfo_endpoint');
            $headers = [
                'Authorization' => 'Bearer '.$token->getAccessToken(),
                'Accept' => 'application/json',
            ];

            $response = $this->httpClient->request('GET', $url, ['headers' => $headers]);

            if (200 !== $response->getStatusCode()) {
                throw new Exception('Was not able to get userinfo (not 200)');
            }

            $user = $response->getBody()->getContents();
            $user = json_decode($user, true);

            // Validate retrieved user is owner of token
            $token->validateSub($user['sub'] ?? '');
        } catch (GuzzleException $e) {
            $this->logException($e);
        } catch (Exception $e) {
            Log::error('[Keycloak Service] '.print_r($e->getMessage(), true));
        }

        return $user;
    }

    /**
     * Retrieve Token from Session.
     */
    public function retrieveToken(): ?array
    {
        return session()->get(self::KEYCLOAK_SESSION);
    }

    /**
     * Save Token to Session.
     *
     * @param mixed $credentials
     */
    public function saveToken($credentials)
    {
        session()->put(self::KEYCLOAK_SESSION, $credentials);
        session()->save();
    }

    /**
     * Remove Token from Session.
     */
    public function forgetToken()
    {
        session()->forget(self::KEYCLOAK_SESSION);
        session()->save();
    }

    /**
     * Validate State from Session.
     *
     * @param mixed $state
     */
    public function validateState($state): bool
    {
        $challenge = session()->get(self::KEYCLOAK_SESSION_STATE);

        return !empty($state) && !empty($challenge) && $challenge === $state;
    }

    /**
     * Save State to Session.
     */
    public function saveState()
    {
        session()->put(self::KEYCLOAK_SESSION_STATE, $this->state);
        session()->save();
    }

    /**
     * Remove State from Session.
     */
    public function forgetState()
    {
        session()->forget(self::KEYCLOAK_SESSION_STATE);
        session()->save();
    }

    /**
     * Build a URL with params.
     */
    public function buildUrl(string $url, array $params): string
    {
        $parsedUrl = parse_url($url);
        if (empty($parsedUrl['host'])) {
            return trim($url, '?').'?'.Arr::query($params);
        }

        if (!empty($parsedUrl['port'])) {
            $parsedUrl['host'] .= ':'.$parsedUrl['port'];
        }

        $parsedUrl['scheme'] = (empty($parsedUrl['scheme'])) ? 'https' : $parsedUrl['scheme'];
        $parsedUrl['path'] = (empty($parsedUrl['path'])) ? '' : $parsedUrl['path'];

        $url = $parsedUrl['scheme'].'://'.$parsedUrl['host'].$parsedUrl['path'];
        $query = [];

        if (!empty($parsedUrl['query'])) {
            $parsedUrl['query'] = explode('&', $parsedUrl['query']);

            foreach ($parsedUrl['query'] as $value) {
                $value = explode('=', $value);

                if (count($value) < 2) {
                    continue;
                }

                $key = array_shift($value);
                $value = implode('=', $value);

                $query[$key] = urldecode($value);
            }
        }

        $query = array_merge($query, $params);

        return $url.'?'.Arr::query($query);
    }

    /**
     * Return the client id for requests.
     */
    protected function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * Return the state for requests.
     */
    protected function getState(): string
    {
        return $this->state;
    }

    /**
     * Return a value from the Open ID Configuration.
     */
    protected function getOpenIdValue(string $key): string
    {
        if (!$this->openid) {
            $this->openid = $this->getOpenIdConfiguration();
        }

        return Arr::get($this->openid, $key);
    }

    /**
     * Retrieve OpenId Endpoints.
     */
    protected function getOpenIdConfiguration(): array
    {
        $cacheKey = 'keycloak_web_guard_openid-'.$this->realm.'-'.md5($this->baseUrl);

        // From cache?
        if ($this->cacheOpenid) {
            $configuration = Cache::get($cacheKey, []);

            if (!empty($configuration)) {
                return $configuration;
            }
        }

        // Request if cache empty or not using
        $url = $this->baseUrl.'/realms/'.$this->realm;
        $url = $url.'/.well-known/openid-configuration';

        $configuration = [];

        try {
            $response = $this->httpClient->request('GET', $url);

            if (200 === $response->getStatusCode()) {
                $configuration = $response->getBody()->getContents();
                $configuration = json_decode($configuration, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);

            throw new Exception('[Keycloak Error] It was not possible to load OpenId configuration: '.$e->getMessage());
        }

        // Save cache
        if ($this->cacheOpenid) {
            Cache::put($cacheKey, $configuration);
        }

        return $configuration;
    }

    /**
     * Check we need to refresh token and refresh if needed.
     */
    protected function refreshTokenIfNeeded(array $credentials): array
    {
        if (!is_array($credentials) || empty($credentials['access_token']) || empty($credentials['refresh_token'])) {
            return $credentials;
        }

        $token = new KeycloakAccessToken($credentials);
        if (!$token->hasExpired()) {
            return $credentials;
        }

        $credentials = $this->refreshAccessToken($credentials);

        if (empty($credentials['access_token'])) {
            $this->forgetToken();

            return [];
        }

        $this->saveToken($credentials);

        return $credentials;
    }

    /**
     * Log a GuzzleException.
     */
    protected function logException(GuzzleException $e)
    {
        // Guzzle 7
        if (!method_exists($e, 'getResponse') || empty($e->getResponse())) {
            Log::error('[Keycloak Service] '.$e->getMessage());

            return;
        }

        $error = [
            'request' => method_exists($e, 'getRequest') ? $e->getRequest() : '',
            'response' => $e->getResponse()->getBody()->getContents(),
        ];

        Log::error('[Keycloak Service] '.print_r($error, true));
    }

    /**
     * Return a random state parameter for authorization.
     */
    protected function generateRandomState(): string
    {
        return bin2hex(random_bytes(16));
    }
}
