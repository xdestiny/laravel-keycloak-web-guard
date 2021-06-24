<?php

namespace Vizir\KeycloakWebGuard\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static string getLoginUrl()
 * @method static string getLogoutUrl()
 * @method static string getRegisterUrl()
 * @method static array getAccessToken(string $code)
 * @method static array refreshAccessToken($credentials)
 * @method static bool invalidateRefreshToken($refreshToken)
 * @method static array getUserProfile(array $credentials)
 * @method static array|null retrieveToken()
 * @method static void saveToken($credentials)
 * @method static void forgetToken()
 * @method static bool validateState($state)
 * @method static void saveState()
 * @method static void forgetState()
 * @method static string buildUrl($url, $params)
 */
class KeycloakWeb extends Facade
{
    /**
     * Get the registered name of the component.
     */
    protected static function getFacadeAccessor(): string
    {
        return 'keycloak-web';
    }
}
