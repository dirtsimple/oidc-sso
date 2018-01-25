<?php
namespace oidc_sso;

class Error {

	static function log($err, $ctx) {
		$handler = apply_filters('oidc_sso_error_logger', null, $err, $ctx);
		if (!empty($handler)) {
			$handler($err, $ctx);
		} else {
			error_log("Error during $ctx: " . json_encode($err, JSON_PRETTY_PRINT));
		}
	}

	static function handle($err, $ctx) {
		static::log($err, $ctx);
		$handler = apply_filters('oidc_sso_error_handler', null, $err, $ctx);
		if (!empty($handler)) $handler($err, $ctx);
	}

	/* Error handling stubs for future use

	// Error codes issued by the plugin
	static function code_invalid_id_token() {}
	static function code_invalid_state() {}
	static function code_incomplete_user_claim() {}

	// HTTP errors for fetching tokens or user info (authorize, refresh, userinfo)
	static function code_http_failure() {}
	static function code_http_request_failed() {}

	// Wordpress errors inserting or updating a user (user_update, user_create)
	static function code_empty_user_login() {}
	static function code_user_login_too_long() {}
	static function code_existing_user_login() {}
	static function code_invalid_username() {}
	static function code_user_nicename_too_long() {}
	static function code_existing_user_email() {}

	// OIDC errors ( https://openid.net/specs/openid-connect-core-1_0.html#AuthError )
	static function code_oidc_interaction_required() {}
	static function code_oidc_login_required() {}
	static function code_oidc_account_selection_required() {}
	static function code_oidc_consent_required() {}
	static function code_oidc_invalid_request_uri() {}
	static function code_oidc_invalid_request_object() {}
	static function code_oidc_request_not_supported() {}
	static function code_oidc_request_uri_not_supported() {}
	static function code_oidc_registration_not_supported() {}

	// OAuth errors ( https://tools.ietf.org/html/rfc6749#section-4.1.2.1 and #section-4.2.2.1)
	static function code_oidc_invalid_request() {}
	static function code_oidc_unauthorized_client() {}
	static function code_oidc_access_denied() {}
	static function code_oidc_unsupported_response_type() {}
	static function code_oidc_invalid_scope() {}
	static function code_oidc_server_error() {}
	static function code_oidc_temporarily_unavailable() {}

	// OAuth Token Fetch Errors ( https://tools.ietf.org/html/rfc6749#section-5.2 )
	static function code_oidc_invalid_grant() {}  // during refresh = user logged out in another window
	static function code_oidc_invalid_client() {}
	static function code_oidc_unsupported_grant_type() {}

	*/
}
