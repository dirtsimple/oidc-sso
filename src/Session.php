<?php
namespace oidc_sso;

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

	protected function varloc($key) { return ($key !== 'expiration' && $key !== 'login') ? 'sso' : 'all'; }

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
			Error::log($resp, 'refresh');
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



