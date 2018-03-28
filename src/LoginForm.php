<?php
namespace oidc_sso;

class LoginForm {
	static function action_login_init() {
		global $action;

		// leave login enabled until all settings configured
		if (! Plugin::is_configured() ) return;

		$class = static::class;
		if ( method_exists($class, $action) ) {
			# override actions with our methods
			$method = "$class::$action";
			$method();
			return;
		}

		// Treat lost password, etc. as logins handled by the IdP
		static::login();
	}

	static function get_redirect() {
		return wp_unslash(get($_GET['redirect_to'], ''));
	}

	static function register() {
		static::login( empty( Plugin::settings()->endpoint_register ) ? 'login' : 'register' );
	}

	// enable post/page password functionality
	static function postpass() { return; }

	static function login($endpoint='login') {
		if ( !empty($_GET['state']) ) {
			IdP::authorize(wp_unslash($_GET));
		} else {
			// Ensure max_age is set if a reauth is requested
			if ( !empty($_REQUEST['reauth']) ) $_GET['max_age'] = get($_GET['max_age'], '0');

			if ( !is_user_logged_in() || isset($_GET['max_age']) ) {
				IdP::login(wp_unslash($_GET), $endpoint);
			} else {
				// Already logged in and no re-auth requested: just redirect
				IdP::safe_redirect( static::get_redirect() );
			}
		}
		exit;
	}

	static function logout() {
		check_admin_referer('log-out');
		IdP::logout( static::get_redirect() );
		exit;
	}
}
