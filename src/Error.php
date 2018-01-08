<?php
namespace oidc_sso;

class Error {

	static function log($err, $ctx) {
		$handler = apply_filters('oidc_sso_error_logger', null, $err, $ctx);
		if (!empty($handler)) {
			$handler($err, $ctx);
		} else {
			# XXX log to PHP error_log
		}
	}

	static function handle($err, $ctx) {
		static::log($err, $ctx);
		$handler = apply_filters('oidc_sso_error_handler', null, $err, $ctx);
		if (!empty($handler)) $handler($err, $ctx);
	}

}
