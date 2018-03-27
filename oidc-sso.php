<?php
/*
Plugin Name:  OpenID Connect Single Sign-On
Plugin URI:   https://github.com/pjeby/oidc-sso/
Description:  Replace WP login+registration with an OIDC IdP
Version:      0.3.2
Author:       PJ Eby
Author URI:   https://github.com/pjeby
License:      GPL2
License URI:  https://www.gnu.org/licenses/gpl-2.0.html
*/

namespace oidc_sso;

const LAST   = 99999999;
const FIRST  = -99999999;

const OPTION_NAME ='oidc_sso';
const REQUIRED_SETTINGS = 'client_id endpoint_login endpoint_token scope username_format nickname_format email_format displayname_format';

/* Convenience functions */

function get(&$var, $default=false) { return isset($var) ? $var : $default; }

function static_filter($class, $tag, $priority=10, $accepted_args=1, $method='') {
	if ( empty($method) ) $method = "filter_$tag";
	return add_filter($tag, "$class::$method", $priority, $accepted_args);
}

function static_action($class, $tag, $priority=10, $accepted_args=1) {
	return add_action($tag, "$class::action_$tag", $priority, $accepted_args);
}

function trap($value, $context) {
	if ( !is_wp_error($value) ) return $value;
	Error::handle($value, $context);
	wp_die($value);  # default if no handler
}



class Plugin {
	protected static $settings;

	static function settings() {
		if ( empty(static::$settings) ) {
			$defaults = array(
				'client_id'         => '',
				'client_secret'     => '',
				'scope'             => 'openid',
				'endpoint_login'    => '',
				'endpoint_userinfo' => '',
				'endpoint_token'    => '',
				'endpoint_end_session' => '',
                'endpoint_register' => '',
				'http_request_timeout' => 5,
				'username_format'    => '{random:5}',
				'nickname_format'    => '{given name} {family_name:1}',
				'email_format'       => '{email}',
				'displayname_format' => '{given name} {family_name:1}',
				'silent_login'       => 0
			);
			static::$settings = (object) array_replace_recursive($defaults, get_option(OPTION_NAME, array()));
		}
		return static::$settings;
	}

	static function is_configured() {
		$s = static::settings();
		foreach (explode(' ', REQUIRED_SETTINGS) as $key) if ( empty($s->$key) ) return false;
		return true;
	}

	static function safe_to_redirect() {
		return $_SERVER['REQUEST_METHOD'] === 'GET' && $GLOBALS['pagenow'] !== 'wp-login.php';
	}

	static function always_redirect($url, $redirect='') {
		// Always redirect to origin page
		if ( empty($redirect) ) $url = add_query_arg('redirect_to', urlencode($_SERVER['REQUEST_URI']), $url);
		return $url;
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
					$user_id = false;
				}
			}
		}

		if ( ! $user_id && !empty($interval = static::settings()->silent_login) ) {
			// We only do silent login if the cookie is set, to prevent redirect loops
			$attempt = get($_COOKIE['oidc_sso_last_login_attempt'], 0);
			if ( !empty($attempt) && time() > intval($attempt) + $interval * 60 ) {
				static::maybe_login();
			}
		}
		return $user_id;
	}

	static function maybe_login($arg='prompt', $val='none') {
		if ( ! static::safe_to_redirect() ) return;
		wp_redirect( add_query_arg($arg, urlencode($val), wp_login_url($_SERVER['REQUEST_URI'])) );
		exit;
	}

	static function recent_login($max_age=3600, $redirect=true) {
		if (is_user_logged_in() && time() - Session::current()->auth_time() <= $max_age) return true;
		if ($redirect) static::maybe_login('max_age', $max_age);
		return false; // no $redirect or not safe to redirect
	}



	static function filter_plugin_action_links($links) {
		if ( current_user_can( 'manage_options' ) )  {
			array_unshift($links, '<a href="users.php?page=oidc_sso-settings">'. __( 'Settings' ) . '</a>');
		}
		return $links;
	}
}


/* Bootstrap */

static_filter( Plugin::class, 'determine_current_user', LAST );

static_filter( Plugin::class, 'login_url',        LAST, 2, 'always_redirect');
static_filter( Plugin::class, 'logout_url',       LAST, 2, 'always_redirect');
static_filter( Plugin::class, 'lostpassword_url', LAST, 2, 'always_redirect');
static_filter( Plugin::class, 'register_url',     LAST, 2, 'always_redirect');

add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array(Plugin::class, 'filter_plugin_action_links'));

static_action( Settings::class, 'admin_menu' );
static_action( LoginForm::class, 'login_init', FIRST );



















