<?php

namespace Vizir\KeycloakWebGuard\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Routing\Redirector;
use Illuminate\Support\Facades\Auth;
use Vizir\KeycloakWebGuard\Exceptions\KeycloakCallbackException;
use Vizir\KeycloakWebGuard\Facades\KeycloakWeb;

class AuthController extends Controller
{
    /**
     * Redirect to login.
     *
     * @return Redirector|RedirectResponse
     */
    public function login()
    {
        $url = KeycloakWeb::getLoginUrl();
        KeycloakWeb::saveState();

        return redirect($url);
    }

    /**
     * Redirect to logout.
     *
     * @return Redirector|RedirectResponse
     */
    public function logout()
    {
        KeycloakWeb::forgetToken();

        $url = KeycloakWeb::getLogoutUrl();

        return redirect($url);
    }

    /**
     * Redirect to register.
     *
     * @return Redirector|RedirectResponse
     */
    public function register()
    {
        $url = KeycloakWeb::getRegisterUrl();

        return redirect($url);
    }

    /**
     * Keycloak callback page.
     *
     * @throws KeycloakCallbackException
     *
     * @return Redirector|RedirectResponse
     */
    public function callback(Request $request)
    {
        // Check for errors from Keycloak
        if (!empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            throw new KeycloakCallbackException($error);
        }

        // Check given state to mitigate CSRF attack
        $state = $request->input('state');
        if (empty($state) || !KeycloakWeb::validateState($state)) {
            KeycloakWeb::forgetState();

            throw new KeycloakCallbackException('Invalid state');
        }

        // Change code for token
        $code = $request->input('code');
        if (!empty($code)) {
            $token = KeycloakWeb::getAccessToken($code);

            if (Auth::validate($token)) {
                $url = config('keycloak-web.redirect_url', '/admin');

                return redirect()->intended($url);
            }
        }

        return redirect(route('keycloak.login'));
    }
}
