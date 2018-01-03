<?php
namespace oidc_sso;

class LoginForm {

	static function action_login_init() {
		global $action;
		$class = static::class;

		if ( method_exists($class, $action) ) {
			# override actions with our methods
			$method = "$class::$action";
			$method();
			return;
		}

		# Treat register, lost password, etc. as logins handled by the IdP
		static::login();
	}

	static function postpass() {
		# enable post/page password functionality
		return;
	}

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
