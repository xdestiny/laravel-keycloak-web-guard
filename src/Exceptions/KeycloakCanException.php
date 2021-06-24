<?php

namespace Vizir\KeycloakWebGuard\Exceptions;

use Illuminate\Auth\AuthenticationException;

class KeycloakCanException extends AuthenticationException
{
    /**
     * Keycloak Callback Error
     *
     * @param string|null     $message  [description]
     * @param \Throwable|null $previous [description]
     * @param array           $headers  [description]
     * @param int|integer     $code     [description]
     */
    public function __construct(string $error = '')
    {
        $message = '[Keycloak Error] ' . $error;

        parent::__construct($message);
    }
}
