<?php
namespace oidc_sso;

class Identity {

	const META_KEY='openid-connect-generic-subject-identity';
	public $id_claim, $subject;
	protected $tokens, $userinfo;

	function __construct($token_response) {
		$this->tokens = $token_response;
		$this->id_claim = UnverifiedJWT::decode($token_response['id_token']);
		$this->subject = $this->id_claim->sub;
	}

	function login() {
		$user = $this->user();
		$session = new Session($user->ID);
		$session->authorize($this->tokens);
		do_action( 'wp_login', $user->user_login, $user );
	}

	function user() {
		# XXX filter 'insert_user_meta' so META_KEY can be set before profile_update/user_register?
		if ( is_user($user = $this->find_user()) ) {
			$user_id = $user->ID;
			trap( wp_update_user($this->userdata($user)), 'user_update');
		} else {
			$user_id = trap( wp_insert_user($this->userdata()), 'user_create');
			$user = get_user_by('ID', $user_id);
		}
		update_user_meta( $user_id, static::META_KEY, (string) $this->subject );
		return $user;
	}

	function find_user() {
		$users = get_users(array('meta_key' => static::META_KEY, 'meta_value' => (string) $this->subject));
		if (!empty($users)) return $users[0];
		return get_user_by('email', $this->email);
	}

	function userdata($user=null) {
		$data = array(
			'user_email'   => $this->format('email'),
			'display_name' => $this->format('displayname'),
			'nickname'     => $this->format('nickname'),
			'first_name'   => isset($this->given_name)  ? $this->given_name  : '',
			'last_name'    => isset($this->family_name) ? $this->family_name : '',
		);

		if ( is_user($user) ) {
			$data['ID'] = $user->ID;
		} else {
			$data['user_login'] = $this->unique_login($this->format('username'), $user);
			$data['user_pass']  = wp_generate_password( 32, TRUE, TRUE );
		}
		return apply_filters('oidc_sso_userdata', $data, $this, $user);
	}

	function __get($key) {
		if ($key==='random') return md5( mt_rand() . microtime( true ) );
		if (isset($this->id_claim->$key)) return $this->id_claim->$key;
		$userinfo = $this->userinfo();
		return isset($userinfo[$key]) ? $userinfo[$key] : null;
	}

	function __isset($key) {
		return $key==='random' || isset($this->id_claim->$key) || isset($this->userinfo()[$key]);
	}

	function unique_login($name, $user=null) {
		$name = sanitize_user( explode('@', $name)[0] ); $username = $name; $count = 1;
		$user_id = is_user($user) ? $user->ID : 0;
		while ( ($uid = username_exists($username)) && $uid != $user_id) $username = $name . ++$count;
		return $username;
	}






	protected function expression($format) {
		foreach(explode('||', $format) as $alt) {
			try {
				return preg_replace_callback('/\{([^}]+)\}/u', array($this, '__lookup'), $alt);
			} catch (\Exception $e) { continue; }
		}
		return trap( new \WP_Error( 'incomplete_user_claim', __( 'User claim incomplete' ), $format ), 'userinfo' );
	}

	protected function __lookup($matches) {
		$keys = array_filter(explode('|', $matches[1]));
		foreach ($keys as $key) {
			list ($key, $max) = explode(':', $key) + array(1=>255);
			if (isset($this->$key) && !empty($this->$key)) return mb_substr($this->$key, 0, $max, 'UTF-8');
		}
		throw new \Exception("No match for " . $matches[1]);
	}

	protected function format($key) {
		$settings = Plugin::settings();
		$format = get($settings->{$key . '_format'}, '');
		return $this->expression($format);
	}

	protected function userinfo() {
		if (isset($this->userinfo)) return $this->userinfo;
		return $this->userinfo = IdP::fetch_userinfo($this->tokens['access_token'], $this->subject);
	}

}

function is_user($user) {
	return is_a( $user, 'WP_User' ) && $user->exists();
}







