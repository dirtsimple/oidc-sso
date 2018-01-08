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

}
