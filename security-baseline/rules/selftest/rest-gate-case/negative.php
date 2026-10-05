<?php
// wp-rest-gate-case fixture — NEGATIVE: gates a re-cased route cannot walk past, and code out of scope.
// Nothing in this file may fire.

// strtolower on both sides
add_filter( 'rest_pre_dispatch', 'sb_lower_gate', 10, 3 );
function sb_lower_gate( $result, $server, $request ) {
	$route = strtolower( (string) $request->get_route() );
	// ok: wp-rest-gate-case
	if ( ! str_starts_with( $route, strtolower( '/SB-NS/v1/' ) ) ) {
		return $result;
	}
	return sb_secret_ok( $request ) ? $result : new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
}

// lower-cased inline, mb_strtolower too
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	// ok: wp-rest-gate-case
	if ( str_starts_with( mb_strtolower( $request->get_route() ), '/sb-ns/v1/' ) && ! sb_secret_ok( $request ) ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	return $result;
}, 10, 3 );

// stripos (how the CF7 gate was fixed)
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	// ok: wp-rest-gate-case
	if ( false === stripos( (string) $request->get_route(), '/contact-form-7/' ) ) {
		return $result;
	}
	return sb_cf7_proxy_ok() ? $result : new WP_Error( 'proxy_required', 'Forbidden.', array( 'status' => 403 ) );
}, 10, 3 );

// preg_match with the i modifier, and with an inline (?i)
add_filter( 'rest_request_before_callbacks', function ( $response, $handler, $request ) {
	// ok: wp-rest-gate-case
	if ( preg_match( '#^/sb-ns/v1/#i', $request->get_route() ) && ! sb_secret_ok( $request ) ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	// ok: wp-rest-gate-case
	if ( preg_match( '#(?i)^/sb-other/v1/#', $request->get_route() ) && ! sb_secret_ok( $request ) ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	return $response;
}, 10, 3 );

// strcasecmp / str_istarts_with (a polyfill) / substr_compare with case_insensitive on
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	$route = $request->get_route();
	// ok: wp-rest-gate-case
	if ( 0 !== strncasecmp( $route, '/sb-ns/', 7 ) ) {
		return $result;
	}
	// ok: wp-rest-gate-case
	if ( ! str_istarts_with( $route, '/sb-ns/v1/' ) ) {
		return $result;
	}
	// ok: wp-rest-gate-case
	if ( 0 !== substr_compare( $route, '/sb-ns/', 0, 7, true ) ) {
		return $result;
	}
	return sb_secret_ok( $request ) ? $result : new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
}, 10, 3 );

// The fix this check recommends: the gate in each route's permission_callback, no path parsing.
add_action( 'rest_api_init', function () {
	register_rest_route( 'sb-ns/v1', '/submit', array(
		'methods'             => 'POST',
		'callback'            => 'sb_submit',
		'permission_callback' => 'sb_require_proxy_secret',
	) );
} );
function sb_require_proxy_secret( WP_REST_Request $request ) {
	// ok: wp-rest-gate-case
	return hash_equals( (string) SB_PROXY_SECRET, (string) $request->get_header( 'x-sb-proxy' ) );
}

// A route test on a hook this check does not grade (CORS headers, not a gate).
add_filter( 'rest_pre_serve_request', function ( $served, $result, $request ) {
	// ok: wp-rest-gate-case
	if ( strpos( $request->get_route(), '/wc/store' ) === 0 ) {
		header( 'Access-Control-Allow-Origin: *' );
	}
	return $served;
}, 10, 3 );

// Fails CLOSED on a re-cased route: an exemption taken on a MATCH, a denial taken on a MISMATCH.
add_filter( 'rest_authentication_errors', function ( $result ) {
	if ( ! empty( $result ) ) {
		return $result;
	}
	$route = $GLOBALS['wp']->query_vars['rest_route'] ?? '';
	// ok: wp-rest-gate-case
	if ( str_starts_with( $route, '/contact-form-7/' ) ) {
		return $result; // public: a re-cased request is simply not exempted
	}
	foreach ( array( '/sb-public/v1/', '/oembed/1.0/' ) as $open ) {
		// ok: wp-rest-gate-case
		if ( str_starts_with( $route, $open ) ) {
			return $result;
		}
	}
	return is_user_logged_in() ? $result : new WP_Error( 'rest_forbidden', 'Login required.', array( 'status' => 401 ) );
} );
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	// ok: wp-rest-gate-case
	if ( ! str_starts_with( $request->get_route(), '/sb-only/v1/' ) ) {
		return new WP_Error( 'rest_disabled', 'Only sb-only/v1 is served here.', array( 'status' => 404 ) );
	}
	return $result;
}, 10, 3 );

// Comparisons with no letters, the REST URL prefix, and values that are not the route string.
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	$route = $request->get_route();
	// ok: wp-rest-gate-case
	if ( '' === $route || '/' === $route ) {
		return $result;
	}
	$uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
	// ok: wp-rest-gate-case
	if ( false === strpos( $uri, '/' . rest_get_url_prefix() . '/' ) ) {
		return $result;
	}
	// ok: wp-rest-gate-case
	if ( count( explode( '/', trim( $route, '/' ) ) ) > SB_MAX_DEPTH || strlen( $route ) === SB_MAX_LEN ) {
		return new WP_Error( 'too_deep', 'Too deep.', array( 'status' => 400 ) );
	}
	return $result;
}, 10, 3 );

// A reasoned waiver.
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	// lint-allow-wp-rest-gate-case: logging only — the gate is each route's permission_callback
	// ok: wp-rest-gate-case
	$is_ours = str_starts_with( $request->get_route(), '/sb-ns/v1/' );
	if ( $is_ours ) {
		sb_log_hit();
	}
	return $result;
}, 10, 3 );

// A helper whose direction fails closed: a MATCH exempts (public), so a re-cased route is not exempted.
add_filter( 'rest_pre_dispatch', array( 'SB_Public_Helper', 'gate' ), 10, 3 );
class SB_Public_Helper {
	public static function gate( $result, $server, $request ) {
		if ( self::is_not_public( $request ) && ! sb_secret_ok( $request ) ) {
			return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
		}
		return $result;
	}
	private static function is_not_public( $request ) {
		// ok: wp-rest-gate-case
		if ( str_starts_with( $request->get_route(), '/sb-public/v1/' ) ) {
			return false;
		}
		return true;
	}
}
