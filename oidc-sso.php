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


/* Convenience functions */

function get(&$var, $default=false) { return isset($var) ? $var : $default; }

function static_filter($class, $tag, $priority=10, $accepted_args=1, $method='') {
	if ( empty($method) ) $method = "filter_$tag";
	return add_filter($tag, "$class::$method", $priority, $accepted_args);
}

function static_action($class, $tag, $priority=10, $accepted_args=1) {
	return add_action($tag, "$class::action_$tag", $priority, $accepted_args);
}

function maybe_throw($value) {
	if ( !is_wp_error($value) ) return $value;
	wp_die($value); # XXX throw something, log etc.
}




class Plugin {

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

	static function always_redirect($url, $redirect='') {
		// Always redirect to origin page
		if ( empty($redirect) ) $url = add_query_arg('redirect_to', $_SERVER['REQUEST_URI'], $url);
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
					return false;
				}
			}
		}
		return $user_id;
	}

	static function action_admin_init() {
		# Register settings page
	}

}


/* Bootstrap */

static_filter( Plugin::class, 'determine_current_user', LAST );

static_filter( Plugin::class, 'login_url',        LAST, 2, 'always_redirect');
static_filter( Plugin::class, 'logout_url',       LAST, 2, 'always_redirect');
static_filter( Plugin::class, 'lostpassword_url', LAST, 2, 'always_redirect');
static_filter( Plugin::class, 'register_url',     LAST, 2, 'always_redirect');

static_action( Plugin::class, 'admin_init' );
static_action( LoginForm::class, 'login_init', FIRST );




