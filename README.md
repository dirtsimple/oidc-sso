# OpenID Connect Single-SignOn for WP

This is an OpenID Connect single-signon plugin for Wordpress, similar in many respects to [daggerhart/openid-connect-generic](https://github.com/daggerhart/openid-connect-generic), but with a few critical differences in purpose.  Specifically:

* It's designed to be used by *front-end* users (e.g. LearnDash, Woocommerce, etc.), rather than back-end users.  So it always redirects to the origin page of a login/logout, and tries not to *ever* give the user an error message if possible.

* It's intended to completely *replace* Wordpress's login system, rather than supplement it, disabling any login or signup that isn't done via the identity provider.  Properties mapped from the identity provider override those set in Wordpress, *every time* the user logs in.  If a user wants to change their email address, name, nickname, etc., they have to change it at the IdP or it'll be reset.

  (This is by design: if you're trying to do single signon with an IdP in the first place, you want this stuff consistent across sites sharing the login.)

It also adds a few minor features, like:

* More sophisticated mapping of user info: instead of just `{fieldname}`, you can use `{fieldA|fieldB:5}` to get either the contents of `fieldA` or the first 5 Unicode chars of `fieldB`.  You can also use `||` to separate alternatives at a higher level, like setting the `displayname` format to `{user_alias}||{given_name} {family_name:1}.` to make a person's display name their `user_alias` property or else their first name and last initial.

  You can also use the field `random` to include a random value in the user's login name, e.g `random:5` to make a user's login a random 5-digit hex string.  (De-duplication is automatic.)  Since users will never use it to log in anyway, it avoids relating a user's login or permalink to any personally identifying information such as their name or email address.

* Automatic session extension so a session won't be logged out after `auth_cookie_expiration`, as long as the user hits the site often enough to avoid refresh token timeout.

* Token refresh is handled before other plugins are loaded and avoids generating a logout event or visible effects for timed-out or otherwise-invalidated sessions

* You can pass arguments to the IdP by adding them to `login_url()`: both the standards-defined `prompt`, `max_age`, `login_hint`, `ui_locales`, and the Keycloak-specific `kc_idp_hint`.

* Wordpress's user registration URL is redirected to your IdP login page (or if you're using Keycloak, AWS, or another IdP with registration flow, it can redirect to the registration flow instead).

* An experimental "silent login" feature allows users to be automatically logged in to Wordpress as long as they are already logged in at the IdP in the same browser.

* An API for requiring login freshness (e.g. for account management pages, placing orders, etc.): `oidc_sso\Plugin::recent_login($timeout=3600, $redirect=true)` will redirect through a login page if it's been longer than `$timeout` since the user logged in.  Returns true if the session is new enough, false otherwise.  If the session is too old, `$redirect` is true, and it's safe to redirect, the function redirects and exits without returning.  (The purpose of this API is to have a way to do Github-style "sudo mode" or Amazon's allowing you to browse for long periods but requiring a recent login for more secure pages.)

It also does NOT support these features, by design:

* Making a site private (there are other plugins for that)
* NOT linking existing users, or linking them by anything other than email address or IdP subject identity
* Disabling SSL verification (a horrifically bad idea)
* The available actions and filters are different, and still subject to change.  In general, API calls made to the plugin are preferred over filtering within the plugin, and single shared hooks with more parameters are preferred to multiple variants of similar events.  (e.g., there is one `oidc_sso_userdata` filter for altering user data from the IdP before it hits Wordpress, whether the user is new or existing, instead of three different action hooks).

It also has these requirements, that are not (yet) typical of Wordpress plugins:

* You *must* be using a WP site built on Composer (e.g. using [bedrock](https://github.com/roots/bedrock/)), and install the plugin using Composer, as it uses Composer autoloading rather than registering its own autoloader.
* A modern PHP version is required: 5.2 just won't do.  (I'm testing against 7.1 and a lot of what I'm doing requires at least 5.5, if not 5.6.)

## Issues

This code should be considered alpha: i.e., suitable for developer testing only.  Some issues to be aware of:

* Error handling is very basic.  You need to filter `oidc_sso_error_logger` or `oidc_sso_error_logger` for an error to do anything other than  `error_log()` and `wp_die()` .  In the case of an error during token refresh, the logger is invoked, but the user is silently logged out without a visible error message.  (Though you could change this with an appropriate logger function.)
* The code is not documented and lacks any automated tests.

## Todo

### Error Handling

There are quite a few varieties of error that can happen:

* IdP availability errors such as timeouts, 503s, and the like
* IdP restriction errors such as denied access, consents, unauthorized client, failure to obtain data needed for user fields, etc.
* Errors that indicate either hack attempts (CSRF, replay, spoofing, etc.) or state corruption (rejected cookies, expired cookies, stale pages in other tabs/windows), etc.

Each of these kinds of errors needs to be handled differently in the UI, including where possible an option to go to the same page or to the redirect target page or the home page.  (This should not be done via "back", as the history likely includes IdP login or registration pages.  Note too that some of these errors occur at a redirect endpoint instead of in response to queries made by the plugin to the IdP.)

When refreshing tokens, errors should usually not be displayed, and the user simply logged out silently.  While this may cause users to be logged out in case of temporary availability issues with the IdP, we are largely assuming the IdP is in the same datacenter with the Wordpress site and that restarts of the IdP are likely less frequent than restarts of Wordpress.  These decisions may not play well with more distributed or less-managed environments.

### Wishlist

* Actually verify JWT tokens instead of trusting them blindly
* OIDC discovery so you only have to enter one URL in the config

