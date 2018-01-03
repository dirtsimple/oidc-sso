<?php
/*
Plugin Name:  OpenID Connect Single Sign-On
Plugin URI:   https://github.com/pjeby/oidc-sso/
Description:  Replace WP login+registration with an OIDC IdP
Version:      0.0.1
Author:       PJ Eby
Author URI:   https://github.com/pjeby
License:      GPL2
License URI:  https://www.gnu.org/licenses/gpl-2.0.html
*/

namespace oidc_sso;

const LAST   = 99999999;
const FIRST  = -99999999;

const OPTION_NAME ='openid_connect_generic_settings';  # XXX























class Plugin {

	static function login_url($redirect='', $reauth_after=false, $args=array()) {
		if ( is_int($reauth_after) ) {
			$args['max_age'] = $reauth_after;
		} elseif ( $reauth_after === true ) {
			$args['max_age'] = 0;
		}
		if ( !empty( $redirect ) ) $args['redirect'] = $redirect;
		return Login::url($args);
	}

	static function logout_url($redirect='') {
		return Logout::url( array('redirect' => $redirect, '_wpnonce'=>wp_create_nonce('wp_rest')) );
	}

	protected static $settings;

	static function settings() {
		if ( empty(static::$settings) ) {
			$defaults = array(
				'client_id'         => '',
				'client_secret'     => '',
				'scope'             => '',
				'endpoint_login'    => '',
				'endpoint_userinfo' => '',
				'endpoint_token'    => '',
				'endpoint_end_session' => '',
				'endpoint_register' => '',
				'http_request_timeout' => 5,
			);
			static::$settings = (object) array_replace_recursive($defaults, get_option(OPTION_NAME, array()));
		}
		return static::$settings;
	}

	static function save_settings() {
		update_option(OPTION_NAME, (array) static::settings());
	}


	/**
	 * Don't treat a user as logged in if their SSO expires and can't be refreshed
	 */
	static function filter_determine_current_user($user_id) {
		// Only validate already logged-in users
		if ( $user_id ) {
			$session = Session::current($user_id);

			if ( $session->needs_refresh() ) {
				if ( ! $session->can_refresh() || !$session->do_refresh() ) {
					$session->destroy();
					wp_clear_auth_cookie();
					return false;
				}
			}
		}
		return $user_id;
	}

	static function action_admin_init() {
		# Register settings page
	}
	static function action_login_init() {
		# Register login page overrides
	}

	static function action_rest_api_init() {
		Login::register();
		Logout::register();
		Authcode::register();
	}

	static function filter_logout_url($url, $redirect='') {
		return static::logout_url(empty($redirect) ? $_SERVER['REQUEST_URI'] : $redirect);
	}

	static function filter_login_url($url, $redirect='', $reauth=false) {
		return static::login_url(empty($redirect) ? $_SERVER['REQUEST_URI'] : $redirect, $reauth);
	}
}

class Endpoint {
	const REST_NS = 'oidc-sso';

	static function url($args=array()) {
		$url = rest_url(static::REST_NS . static::PATH);
		if ( ! empty($args) ) $url = add_query_arg($args, $url);
		return $url;
	}

	static function _GET($request) {
		try {
			static::GET($request->get_query_params());
		} catch (Exception $e) {
			Plugin::error_page($e);   # XXX
		}
	}

	static function register() {
		register_rest_route(
			static::REST_NS, static::PATH,
			array('methods' => 'GET', 'callback' => array(static::class, '_GET'))
		);
	}
}

class Login extends Endpoint {
	const PATH='/login';
	static function GET($request) { IdP::login($request); }
}

class Logout extends Endpoint {
	const PATH='/logout';
	static function GET($request) { IdP::logout($request); }
}

class Authcode extends Endpoint {
	const PATH='/authcode';
	static function GET($request) { IdP::authorize($request); }
}


class Session {

	const ALGO = 'aes-256-ctr', SSO_KEY='oidc-sso';

	protected $manager, $all, $sso, $dirty=false;
	public $token, $user_id;

	static function current($user_id = false) {
		global $current_user;
		$class = get_called_class();
		return new $class($user_id ? $user_id : $current_user->ID, wp_get_session_token());
	}

	function __construct($user_id, $token='') {
		$this->user_id = $user_id;
		$this->manager = \WP_Session_Tokens::get_instance( $user_id );
		if ( empty($token) ) $token = $this->new_token();
		$this->token = $token;
		$this->all = $this->manager->get($token);
		$this->sso = $this->deobfuscated( get($this->all[static::SSO_KEY], array('is_sso'=>false)) );
	}

	protected function new_token() {
		return $this->manager->create($this->cookie_expires());
	}

	function destroy() {
		$this->manager->destroy($this->token);
	}

	function __isset( $key ){ return isset ( $this->{$this->varloc($key)}[ $key ] ); }

	function __get( $key ){ return $this->{$this->varloc($key)}[ $key ]; }

	function __set( $key, $value ){
		$this->{$this->varloc($key)}[ $key ] = $value; $this->dirty = true;
	}

	protected function varloc($key) { return $key !== 'expiration' ? 'sso' : 'all'; }


	function needs_refresh() {
		return $this->is_sso && $this->refresh_after < time();
	}

	function can_refresh() {
		// Can refresh if we have a token and it either doesn't expire or hasn't expired yet
		return ! empty($this->refresh_token) && ( ! $this->refresh_expires || time() < $this->refresh_expires );
	}

	function do_refresh() {
		$resp = IdP::fetch_tokens('refresh_token', array('refresh_token'=>$this->refresh_token));
		if ( is_wp_error( $resp ) ) {
			$resp->add( 'refresh_token' , __( 'Refresh token failed.' ) );
			# XXX log the error here
			return false;
		} else {
			$this->authorize($resp);
			return true;
		}
	}

	function authorize($resp) {
		if (!empty($resp[ 'id_token' ])) $this->id_token = $resp[ 'id_token' ];
		$this->is_sso = true;
		$this->access_token  = get( $resp['access_token'],  null );
		$this->session_state = get( $resp['session_state'], null );
		$this->refresh_token = get( $resp['refresh_token'], null );
		$this->last_verified = time();
		$now = time() - IdP::http_timeout();
		$this->refresh_after = $now + $resp['expires_in'];
		$this->refresh_expires = $rex = get( $resp[ 'refresh_expires_in' ], false );
		if ($this->refresh_expires) $this->refresh_expires += $now;

		# update session timeout and refresh cookie
		$this->expiration = $this->cookie_expires();
		wp_set_auth_cookie( $this->user_id, FALSE, '', $this->token);
		$this->save();
	}



	function save() {
		if ($this->dirty) {
			$this->all[static::SSO_KEY] = $this->obfuscated($this->sso);
			$this->manager->update($this->token, $this->all);
			$this->dirty = false;
		}
	}

	function cookie_expires() {
		return time() + apply_filters( 'auth_cookie_expiration', 2 * DAY_IN_SECONDS, $this->user_id, FALSE );
	}

	protected function obfuscated($data) {
		return $this->with_tokens($data, array($this, 'obfuscate'));
	}

	protected function deobfuscated($data) {
		return $this->with_tokens($data, array($this, 'deobfuscate'));
	}

	protected function obfuscate($token) {
		$nonce = openssl_random_pseudo_bytes(openssl_cipher_iv_length(static::ALGO));
		return base64_encode( $nonce . openssl_encrypt($token, static::ALGO, $this->token, OPENSSL_RAW_DATA, $nonce) );
	}

	protected function deobfuscate($token) {
		$ns = openssl_cipher_iv_length(static::ALGO);
		$token = base64_decode($token); $nonce = mb_substr($token, 0, $ns, '8bit');
		return openssl_decrypt(mb_substr($token, $ns, null, '8bit'), static::ALGO, $this->token, OPENSSL_RAW_DATA, $nonce);
	}

	protected function with_tokens($data, $callback) {
		if ( isset($data['access_token']) )  $data['access_token']  = $callback($data['access_token']);
		if ( isset($data['refresh_token']) ) $data['refresh_token'] = $callback($data['refresh_token']);
		return $data;
	}

}



/* Convenience functions */

function get(&$var, $default=false) { return isset($var) ? $var : $default; }

function static_filter($class, $tag, $priority=10, $accepted_args=1) {
	return add_filter($tag, "$class::filter_$tag", $priority, $accepted_args);
}

function static_action($class, $tag, $priority=10, $accepted_args=1) {
	return add_action($tag, "$class::action_$tag", $priority, $accepted_args);
}

function maybe_throw($value) {
	if ( !is_wp_error($value) ) return $value;
	wp_die($value); # XXX throw something, log etc.
}


/* Bootstrap */

static_filter( Plugin::class, 'determine_current_user', LAST );
static_filter( Plugin::class, 'login_url',  LAST, 2 );
static_filter( Plugin::class, 'logout_url', LAST, 3 );
#static_filter( Plugin::class, 'lostpassword_url', LAST);
#static_filter( Plugin::class, 'register_url',     LAST);

static_action( Plugin::class, 'admin_init' );
static_action( Plugin::class, 'rest_api_init' );
static_action( Plugin::class, 'login_init', FIRST );  // disable login page almost entirely












