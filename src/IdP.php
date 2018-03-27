<?php
namespace oidc_sso;

class IdP {
	const STATE_COOKIE = 'oidc-sso-state';

	static function login($params) {
		// Redirect to IdP login with generated state
		$state = static::new_state( get($params['redirect_to'], ''),  get($params['prompt'], ''));
		setcookie('oidc_sso_last_login_attempt', intval(time()), time() + YEAR_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, true, true);
		wp_redirect( static::auth_url($state, $params) ); exit;
	}

	static function authorize($params) {
		$state = trap( static::check_state( get($params['state'], '') ), 'authorize');
		if ( is_user_logged_in() ) wp_logout();  // destroy previous session
		if ( $state->prompt === 'none' && substr_compare( 'xxxxxxxxx' . get($params['error'], ''), '_required', -9 ) === 0 )
			static::safe_redirect( $state->redirect );
		elseif ( !empty($params['error']) ) {
			# per https://openid.net/specs/openid-connect-core-1_0.html#AuthError and https://tools.ietf.org/html/rfc6749#section-4.1.2.1
			$data = array('state' => $state, 'error_uri' => get($params['error_uri'], ''));
			trap( new \WP_Error( 'oidc_' . $params['error'], esc_html(get($params['error_description'], $params['error'])), $data), 'authorize' );
		}
		$tokens = trap( static::fetch_tokens('authorization_code', array('code' => get( $params['code'], ''))), 'authorize' );
		try { $identity = new Identity($tokens); }
		catch ( \Exception $e ) {
			trap( new \WP_Error( 'invalid_id_token', __( 'Invalid id_token' ), $e ), 'authorize' );
		}
		$identity->login();
		static::safe_redirect( $state->redirect );
	}

	static function logout($redirect='') {
		$redirect = static::safe_url($redirect);
		if ( is_user_logged_in() ) {
			$redirect = static::idp_logout_url($redirect);
			wp_logout();
		}
		wp_redirect( $redirect ); exit;
	}

	static function check_state($state) {
		// check state and get redirect value
		$cookie = stripslashes(get($_COOKIE[static::STATE_COOKIE], ''));
		if (empty($state) || empty($cookie) || $state !== wp_hash($cookie)) {
			return new \WP_Error( 'invalid_state', __( 'Invalid state.' ), $state );
		}
		static::set_state_cookie('');  // state can only be used once
		return json_decode($cookie);
	}

	static function auth_url($state, $params) {
		$settings = Plugin::settings();

		$args = array(
			'response_type' => 'code',
			'state'         => $state,
			'scope'         => urlencode($settings->scope),
			'client_id'     => $settings->client_id,
			'redirect_uri'  => site_url('wp-login.php', 'login'),
		);

		foreach (array('prompt', 'max_age', 'login_hint', 'kc_idp_hint', 'ui_locales', ) as $key) {
			if ( isset($params[$key]) ) $args[$key] = $params[$key];
		}

		return add_query_arg($args, $settings->endpoint_login);
	}

	static function new_state($redirect, $prompt) {
		$nonce = md5( mt_rand() . microtime( true ) );
		static::set_state_cookie( $cookie = json_encode(compact('nonce', 'redirect', 'prompt')) );
		return wp_hash($cookie);
	}

	static function set_state_cookie($value) {
		$expire = empty($value) ? time() - YEAR_IN_SECONDS : 0;
		setcookie(static::STATE_COOKIE, $value, $expire, COOKIEPATH, COOKIE_DOMAIN, true, true);
	}



	static function safe_redirect($redirect) {
		wp_safe_redirect( empty($redirect) ? home_url() : $redirect );
		exit;
	}

	protected static function safe_url($redirect) {
		if ( empty($redirect) ) return home_url();
		$redirect = wp_sanitize_redirect($redirect);
		$fallback = apply_filters('wp_safe_redirect_fallback', home_url(), 302);
		$redirect = wp_validate_redirect($redirect, $fallback);
		return $redirect;
	}

	protected static function idp_logout_url($redirect) {
		if ( !empty($logout = Plugin::settings()->endpoint_end_session) ) {
			// log out via OIDC end-session endpoint if specified
			if ( substr($redirect, 0, 1) == '/' ) {
				# An absolute URI is needed
				# XXX this doesn't handle non-standard ports!
				$redirect = (is_ssl() ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $redirect;
			}
			$args = array('post_logout_redirect_uri' => $redirect);
			$session = Session::current();
			if (!empty($session->id_token)) {
				$args['id_token_hint'] = $session->id_token;
			}
			return add_query_arg($args, $logout);
		}
		return $redirect;
	}

	static function http_timeout() {
		return Plugin::settings()->http_request_timeout;
	}

	static function fetch_userinfo($access_token, $subject) {
		if ( empty( Plugin::settings()->endpoint_userinfo ) ) return array();
		$request = array('headers'=>array('Authorization'=>"Bearer $access_token"));
		return trap( static::post('endpoint_userinfo', $request), 'userinfo' );
	}

	static function fetch_tokens($grant_type, $params) {
		$settings = Plugin::settings();

		$params += array(
			'client_id'     => $settings->client_id,
			'client_secret' => $settings->client_secret,
			'grant_type'    => $grant_type,
		);

		if ( $grant_type === 'authorization_code' ) {
			$params += array( 'scope' => urlencode($settings->scope), 'redirect_uri' => site_url('wp-login.php', 'login') );
		}

		return static::post('endpoint_token', array('body' => $params));
	}

	protected static function post($endpoint, $request) {
		$settings = Plugin::settings();

		$request += array('timeout' => $settings->http_request_timeout);
		$request = apply_filters('oidc_sso_remote_request', $request, $endpoint);

		$resp = wp_remote_post($settings->$endpoint, $request);
		if ( is_wp_error($resp) ) return $resp;

		$resp = json_decode( wp_remote_retrieve_body($resp), TRUE );
		if ( isset( $resp[ 'error' ] ) ) {
			return new \WP_Error( 'oidc_' . $resp['error'], esc_html( get( $resp['error_description'], $resp['error'] ) ), $resp );
		}
		return $resp;
	}

}








