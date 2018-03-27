<?php
namespace oidc_sso;

class Settings {
	static $page;
	static function action_admin_menu() { static::$page->register(); }
}


class SettingsPage {

	public $name, $title, $menu_title, $option;
	public $capability='manage_options', $parent='options-general.php', $sections=array();

	function __construct($name, $title, $menu_title='', $sections=array()) {
		$this->name = $name;
		$this->title = $title;
		$this->menu_title = empty($menu_title) ? $title : $menu_title;
		$this->sections = $sections;
	}

	function cap($cap) { $this->capability = $cap; return $this; }
	function option($opt) { $this->option = $opt; return $this; }
	function parent($parent) { $this->parent = $parent; return $this; }
	function sections($sections) { $this->sections = $sections + $this->sections; return $this; }

	function register() {
		empty($this->option) || register_setting($this->name . '-group', $this->option);
		add_submenu_page($this->parent, $this->title, $this->menu_title, $this->capability, $this->name, array($this, 'render'));
		foreach ($this->sections as $id => $section) $section->register($this, $id);
		return $this;
	}

	public function render() {
		?>
		<div class="wrap">
			<h2><?php print esc_html( get_admin_page_title() ); ?></h2>
			<form method="post" action="options.php"><?php
				settings_fields( $this->name . '-group' );
				do_settings_sections( $this->name );
				submit_button();
			?></form>
			<h4><?php _e( 'Notes' ); ?></h4>
			<p class="description">
				<strong><?php _e( 'Redirect URI' ); ?></strong>
				<code><?php print site_url('wp-login.php', 'login'); ?></code>
			</p>
		</div>
		<?php
	}
}


class SettingsGroup {

	public $title, $heading, $fields=array();

	function __construct($title, $heading='', $fields=array()) {
		$this->title = $title;
		$this->heading = $heading;
		$this->fields = $fields;
	}

	function renderHeading() { echo $this->heading; }

	function register($page, $id) {
		add_settings_section($id, $this->title, array($this, 'renderHeading'), $page->name);
		foreach ($this->fields as $fid => $field) {
			$field->register($page, $id, $fid);
		}
	}
}


class TextSetting {

	function __construct($title, $desc, $example='') {
		$this->title = $title;
		$this->desc = $desc;
		$this->example = $example;
	}

	function register($page, $group, $id) {
		$fname = "{$page->option}[$id]";
		add_settings_field($id, $this->title, array($this, 'renderField'), $page->name, $group, array('key'=>$id, 'name'=>$fname));
	}

	function renderField($field) {
		?>
		<input type="text"
		       id="<?php print esc_attr( $field['key'] ); ?>"
		       class="large-text"
		       name="<?php print esc_attr( $field['name'] ); ?>"
		       value="<?php print esc_attr( Plugin::settings()->{ $field['key'] } ); ?>">
		<p class="description">
			<?php print $this->desc; ?>
			<?php if ( !empty( $this->example ) ) : ?>
				<br/><strong><?php _e( 'Example' ); ?>: </strong>
				<code><?php print $this->example; ?></code>
			<?php endif; ?>
		</p>
		<?php
	}

}



Settings::$page = new SettingsPage(
	'oidc_sso-settings',
	__('OpenID Connect Single Sign-on'),
	__('OpenID Connect SSO')
);


Settings::$page->parent('users.php')->option('oidc_sso')->sections( array(

	'client_settings' => new SettingsGroup(
		__( 'Client Settings' ), __('Enter your OpenID Connect identity provider settings'),
		array(
			'client_id' => new TextSetting(
				__('Client ID'),
				__('The ID this client will be recognized as when connecting the to Identity provider server.'),
				'my-wordpress-client-id'
			),
			'client_secret' => new TextSetting(
				__('Client Secret Key'),
				__('Arbitrary secret key the server expects from this client. Can be anything, but should be very unique.')
			),
			'scope' => new TextSetting(
				__('OpenID Scope'),
				__('Space separated list of scopes this client should access.'),
				'email profile openid offline_access'
			),
			'endpoint_login' => new TextSetting(
				__('Login Endpoint URL'),
				__('Identity provider authorization endpoint.'),
				'https://example.com/oauth2/authorize'
			),
			'endpoint_userinfo' => new TextSetting(
				__('Userinfo Endpoint URL'),
				__('Identity provider User information endpoint.'),
				'https://example.com/oauth2/UserInfo'
			),
			'endpoint_token'    => new TextSetting(
				__('Token Validation Endpoint URL'),
				__('Identity provider token endpoint.'),
				'https://example.com/oauth2/token'
			),
			'endpoint_end_session'    => new TextSetting(
				__('End Session Endpoint URL'),
				__('Identity provider logout endpoint.'),
				'https://example.com/oauth2/logout'
			),
			'http_request_timeout'      => new TextSetting(
				__('HTTP Request Timeout'),
				__('Set the timeout for requests made to the IDP. Default value is 5.'),
				30
			),
		)
	),

	'user_fields' => new SettingsGroup(
		__( 'WordPress User Fields' ), __(
			'<p>Specify how identity claims are mapped to Wordpress user fields.</p>' .
			'<p>Enclose field names in <code>{}</code>.  Multiple field names can be separated with <code>|</code>, '.
			'to use the first non-empty field.  You can truncate fields with <code>:</code> and a number, '.
			'e.g. <code>{this:5|that:4}</code> will use the first 5 unicode characters of field <code>this</code>, unless '.
			'it\'s empty, in which case the first 4 characters of field <code>that</code> will be used.</p>'.
			'<p>You can also create higher-level alternatives with <code>||</code>, e.g. '.
			'<code>{alias}||{given_name} {family_name:1).</code> will use the contents of the <code>alias</code> field '.
			'if it exists, otherwise the user\'s first name, last initial, and a <code>.</code> will be used.</p>'.
			'<p>Note that if <em>any</em> field in an expression is empty at runtime, the mapping will '.
			'fail, and if there are no valid alternatives, the user will not be able to register or log in.</p>'
		),
		array(
			'username_format'     => new TextSetting(
				__('Wordpress Login'),
				__('How a new user\'s login should be generated from their identity. You can use <code>random</code> to generate a unique ID automatically, e.g. <code>{random:5}</code> to generate 5-digit hex number.  If a generated login matches an existing login, it will be deduplicated by adding a number, e.g. <code>someuser3</code> if there\'s already a <code>someuser</code> and <code>someuser2</code>.'),
				'{random:5}'
			),
			'nickname_format'     => new TextSetting(
				__('Nickname'),
				__('How a user\'s Wordpress nickname should be generated'),
				'{preferred_username}'
			),
			'email_format'     => new TextSetting(
				__('Email'),
				__('How a user\'s email address should be generated'),
				'{email}'
			),
			'displayname_format'     => new TextSetting(
				__('Display Name Formatting'),
				__('String from which the user\'s display name is built.'),
				'{given_name} {family_name}'
			),
		)
	),
	'other_settings' => new SettingsGroup(
		__( 'Other Settings' ), '',
		array(
			'silent_login' => new TextSetting(
				__('Silent Login Interval'),
				__('How often (in minutes) should we attempt to silently log in a user who\'s already logged in at the identity provider?  0 disables silent login.'),
				60
			)
		)
	),
));
