<?php

/**
 * Mail.ru strategy for Opauth
 * based on http://api.mail.ru/docs/guides/oauth/standalone/
 *          http://api.mail.ru/docs/reference/rest/
 *
 * More information on Opauth: http://opauth.org
 *
 * @copyright    Copyright © 2014 Alexander Filippov
 * @link         http://opauth.org
 * @package      Opauth.MailRuStrategy
 * @license      MIT License
 */
class MailRuStrategy extends OpauthStrategy
{
    /**
     * Compulsory config keys, listed as unassociative arrays
     * eg. array('app_id', 'app_secret');
     */
    public $expects = array('app_id', 'app_secret');

    /**
     * Optional config keys with respective default values, listed as associative arrays
     * eg. array('scope' => 'email');
     */
    public $defaults = array(
        'redirect_uri' => '{complete_url_to_strategy}int_callback',
        'response_type' => 'code',
    );

    /**
     * Auth request
     */
    public function request()
    {
        $url = 'https://connect.mail.ru/oauth/authorize';
        $params = array(
            'client_id' => $this->strategy['app_id'],
            'response_type' => $this->strategy['response_type'],
            'redirect_uri' => $this->strategy['redirect_uri']
        );

        if (!empty($this->strategy['scope'])) {
            $params['scope'] = $this->strategy['scope'];
        }

        $this->clientGet($url, $params);
    }

    /**
     * Internal callback, after Facebook's OAuth
     */
    public function int_callback()
    {
        if (array_key_exists('code', $_GET) && !empty($_GET['code'])) {
            $url = 'https://connect.mail.ru/oauth/token';
            $params = array(
                'client_id' => $this->strategy['app_id'],
                'client_secret' => $this->strategy['app_secret'],
                'grant_type' => 'authorization_code',
                'code' => trim($_GET['code']),
                'redirect_uri' => $this->strategy['redirect_uri'],
            );
            $response = $this->serverPost($url, $params, null, $headers);

            $results = json_decode($response, true);

            if (!empty($results)
                && !empty($results['access_token'])
                && !is_null($me = $this->me($results['access_token']))) {
                $this->auth = array(
                    'provider' => 'MailRu',
                    'uid' => $me->uid,
                    'info' => array(
                        'name' => $me->first_name . ' ' . $me->last_name,
                        'image' => $me->pic
                    ),
                    'credentials' => array(
                        'token' => $results['access_token'],
                        'expires' => date('c', time() + $results['expires_in'])
                    ),
                    'raw' => $me
                );

                if (!empty($me->email)) {
                    $this->auth['info']['email'] = $me->email;
                }
                if (!empty($me->username)) {
                    $this->auth['info']['nickname'] = $me->nick;
                }
                if (!empty($me->first_name)) {
                    $this->auth['info']['first_name'] = $me->first_name;
                }
                if (!empty($me->last_name)) {
                    $this->auth['info']['last_name'] = $me->last_name;
                }
                if (!empty($me->link)) {
                    $this->auth['info']['urls']['mail.ru'] = $me->link;
                }
                if (!empty($me->website)) {
                    $this->auth['info']['urls']['website'] = $me->website;
                }

                $this->callback();
            } else {
                $error = array(
                    'provider' => 'MailRu',
                    'code' => 'access_token_error',
                    'message' => 'Failed when attempting to obtain access token',
                    'raw' => $headers
                );

                $this->errorCallback($error);
            }
        } else {
            $error = array(
                'provider' => 'MailRu',
                'code' => $_GET['error'],
                'message' => $_GET['error_description'],
                'raw' => $_GET
            );

            $this->errorCallback($error);
        }
    }

    private function signature($request_params)
    {
        ksort($request_params);
        $params = '';
        foreach ($request_params as $key => $value) {
            $params .= "$key=$value";
        }
        return md5($params . $this->strategy['app_secret']);
    }

    /**
     * Queries Mail.ru for user info
     *
     * @param string $access_token
     * @return object|null Parsed JSON results
     */
    private function me($access_token)
    {
        $params = array(
            'method' => 'users.getInfo',
            'session_key' => $access_token,
            'app_id' => $this->strategy['app_id'],
            'secure' => 1,
        );
        $params['sig'] = $this->signature($params);
        $me = json_decode($this->serverGet('http://www.appsmail.ru/platform/api', $params, null, $headers));

        if (!empty($me)) {
            return $me[0];
        } else {
            $error = array(
                'provider' => 'MailRu',
                'code' => 'me_error',
                'message' => 'Failed when attempting to query for user information',
                'raw' => array(
                    'response' => $me,
                    'headers' => $headers
                )
            );

            $this->errorCallback($error);
            return null;
        }
    }
}
