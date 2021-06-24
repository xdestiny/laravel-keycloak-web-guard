<?php

namespace Vizir\KeycloakWebGuard\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;

class KeycloakUser implements Authenticatable
{
    /**
     * Attributes we retrieve from Profile.
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'email',
    ];

    /**
     * User attributes.
     *
     * @var array
     */
    protected $attributes = [];

    /**
     * Constructor.
     *
     * @param array $profile Keycloak user info
     */
    public function __construct(array $profile)
    {
        foreach ($profile as $key => $value) {
            if (in_array($key, $this->fillable)) {
                $this->attributes[$key] = $value;
            }
        }

        $this->id = $this->getKey();
    }

    /**
     * Magic method to get attributes.
     *
     * @return mixed
     */
    public function __get(string $name)
    {
        return $this->attributes[$name] ?? null;
    }

    /**
     * Get the value of the model's primary key.
     *
     * @return mixed
     */
    public function getKey()
    {
        return $this->email;
    }

    /**
     * Get the name of the unique identifier for the user.
     */
    public function getAuthIdentifierName(): string
    {
        return 'email';
    }

    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier()
    {
        return $this->email;
    }

    /**
     * Check user has roles.
     *
     * @see KeycloakWebGuard::hasRole()
     *
     * @param array|string $roles
     * @param string       $resource
     *
     * @return bool
     */
    public function hasRole($roles, $resource = '')
    {
        return Auth::hasRole($roles, $resource);
    }

    /**
     * Get the password for the user.
     *
     * @codeCoverageIgnore
     */
    public function getAuthPassword(): string
    {
        throw new \BadMethodCallException('Unexpected method [getAuthPassword] call');
    }

    /**
     * Get the token value for the "remember me" session.
     *
     * @codeCoverageIgnore
     */
    public function getRememberToken(): string
    {
        throw new \BadMethodCallException('Unexpected method [getRememberToken] call');
    }

    /**
     * Set the token value for the "remember me" session.
     *
     * @param string $value
     * @codeCoverageIgnore
     */
    public function setRememberToken($value)
    {
        throw new \BadMethodCallException('Unexpected method [setRememberToken] call');
    }

    /**
     * Get the column name for the "remember me" token.
     *
     * @codeCoverageIgnore
     */
    public function getRememberTokenName(): string
    {
        throw new \BadMethodCallException('Unexpected method [getRememberTokenName] call');
    }
}
