<?php

namespace Vizir\KeycloakWebGuard\Middleware;

use Illuminate\Auth\Middleware\Authenticate;

class KeycloakAuthenticated extends Authenticate
{
    /**
     * Redirect user if it's not authenticated.
     *
     * @param \Illuminate\Http\Request $request
     */
    protected function redirectTo($request): string
    {
        return route('keycloak.login');
    }
}
