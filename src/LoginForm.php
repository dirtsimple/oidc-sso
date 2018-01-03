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

		# disable the login page
		# XXX should probably display an error
		wp_redirect(home_url());
		exit;
	}

	static function postpass() {
		# enable post/page password functionality
		return;
	}

	static function logout() {
		check_admin_referer('log-out');
		IdP::logout( get( $_REQUEST['redirect_to'], '') );
		exit;
	}

}
