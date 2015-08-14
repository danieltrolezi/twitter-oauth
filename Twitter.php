<?php
/**
 * Twitter
 * A simple PHP class that makes more easy to work with themattharris/tmhoauth.
 * themattharris/tmhoauth can be found here: https://github.com/themattharris/tmhOAuth
 *
 * @package resource-twitter
 * @author Daniel Trolezi <danieltrolezi@outlook.com>
 * @author Gabriel Lucas <eu@gabriellucas.com.br>
 * @version 1.0.1
 */

class Twitter extends tmhOAuth
{
    protected $consumerKeys;

	public function __construct($consumerKeys)
	{
        $this->consumerKeys = $consumerKeys;
        parent::__construct($consumerKeys);
	}

    /**
     * @param string $callback
     * @return array
     */
    public function OAuth($callback)
    {
        $twitterOAuthSession = $_SESSION['twitterOAuth'];

        if(!isset($twitterOAuthSession['oauth_verifier'])) {
            if(!isset($_REQUEST['oauth_verifier'])) {
                $request = $this->getRequestToken();
                $twitterOAuthSession['oauth_token'] = $request['oauth_token'];
                $twitterOAuthSession['oauth_token_secret'] = $request['oauth_token_secret'];
                $_SESSION['twitterOAuth'] = $twitterOAuthSession;
                header('Location: '.$this->url('oauth/authenticate', '') . '?oauth_token=' . $request['oauth_token']);
            }
            else {
                $twitterOAuthSession['oauth_token'] = $_REQUEST['oauth_token'];
                $twitterOAuthSession['oauth_token_secret'] = $_REQUEST['oauth_token_secret'];
                $twitterOAuthSession['oauth_verifier'] = $_REQUEST['oauth_verifier'];
                $_SESSION['twitterOAuth'] = $twitterOAuthSession;
                header('Location: '.$callback);
            }
        }
        else {
            $accessToken = $this->getAccessToken($twitterOAuthSession['oauth_token'],$twitterOAuthSession['oauth_verifier']);

            if($accessToken != false) {
                $twitterOAuthSession['oauth_token'] = $accessToken['oauth_token'];
                $twitterOAuthSession['oauth_token_secret'] = $accessToken['oauth_token_secret'];
                $twitterOAuthSession['user_id'] = $accessToken['user_id'];
                $_SESSION['twitterOAuth'] = $twitterOAuthSession;
                return $_SESSION['twitterOAuth'];
            }
            else {
                $_SESSION['twitterOAuth'] = '';
                header('Location: '.$callback);
            }
        }
    }

    /**
     * @return array|bool
     */
    private function getRequestToken()
    {
        $code = $this->apponly_request(array(
            'without_bearer' => true,
            'method' => 'POST',
            'url' => $this->url('oauth/request_token', ''),
            'params' => array(
                'oauth_callback' => 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'],
            ),
        ));

        if ($code != 200)
            return false;

        $response = $this->extract_params($this->response['response']);

        // check the callback has been confirmed
        if ($response['oauth_callback_confirmed'] !== 'true') {
            return false;
        } else {
            return $response;
        }
    }

    /**
     * @param $oauth_token
     * @param $oauth_verifier
     * @return array|bool
     */
    private function getAccessToken($oauth_token, $oauth_verifier)
    {
        $oath = array('oauth_verifier' => $oauth_verifier,  'oauth_token' => $oauth_token);
        $code = $this->request('POST', $this->url('oauth/access_token', ''), $oath, true, false, $this->consumerKeys);

        if ($code != 200)
            return false;

        $response = $this->extract_params($this->response['response']);

        if($response) {
            $this->reconfigure(array_merge($this->consumerKeys, array(
                'token'  => $response['oauth']['oauth_token'],
                'secret' => $response['oauth']['oauth_token_secret'],
            )));

            return $response;
        } else {
            return false;
        }
    }
} 