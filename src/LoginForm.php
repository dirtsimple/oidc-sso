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

		// Treat register, lost password, etc. as logins handled by the IdP
		static::login();
	}

	static function register() {
		// If the IdP is Keycloak, direct register actions to the registration page
		$ep = Plugin::settings()->endpoint_login;
		Plugin::settings()->endpoint_login = preg_replace('\'(/auth/realms/[^/]+/protocol/openid-connect)/auth$\'', '\\1/registrations', $ep);
		static::login();
	}

	// enable post/page password functionality
	static function postpass() { return; }

	static function login() {
		if ( !empty($_GET['state']) ) {
			IdP::authorize($_GET);
		} else {
			if ( !empty($_REQUEST['reauth']) ) $_GET['max_age'] = '0';
			IdP::login($_GET);
		}
		exit;
	}

	static function logout() {
		check_admin_referer('log-out');
		IdP::logout( get( $_REQUEST['redirect_to'], '') );
		exit;
	}
}
