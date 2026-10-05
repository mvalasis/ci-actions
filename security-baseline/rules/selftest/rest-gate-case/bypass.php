<?php
// wp-rest-gate-case fixture — BYPASS CORPUS: the other spellings of the same skippable gate.
// Each `// ruleid:` line must fire. Each would let /wp-json/SB-NS/v1/… (or ?rest_route=/SB-NS/v1/…)
// past the gate while core still dispatches to the sb-ns/v1 handler.

// substr === , strncmp, strcmp on a slice, substr_compare without its flag
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	$route = $request->get_route();
	// ruleid: wp-rest-gate-case
	if ( substr( $route, 0, 11 ) === '/sb-ns/v1/x' ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	// ruleid: wp-rest-gate-case
	if ( 0 === strncmp( $route, '/sb-ns/', 7 ) && ! sb_secret_ok( $request ) ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	// ruleid: wp-rest-gate-case
	if ( strcmp( substr( $route, 0, 7 ), '/sb-ab/' ) !== 0 ) {
		return $result;
	}
	// ruleid: wp-rest-gate-case
	if ( 0 !== substr_compare( $route, '/sb-cd/', 0, 7 ) ) {
		return $result;
	}
	return sb_secret_ok( $request ) ? $result : new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
}, 10, 3 );

// strpos variants, the route assigned and reshaped first
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	$r    = $request->get_route();
	$path = '/' . ltrim( untrailingslashit( $r ), '/' );
	// ruleid: wp-rest-gate-case
	if ( strpos( $path, '/sb-ns/v1' ) !== 0 ) {
		return $result;
	}
	// ruleid: wp-rest-gate-case
	if ( false !== strpos( $path, '/admin-only' ) && ! current_user_can( 'manage_options' ) ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	return $result;
}, 10, 3 );

// explode, then compare a segment; in_array on the segments
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	$parts = explode( '/', trim( $request->get_route(), '/' ) );
	// ruleid: wp-rest-gate-case
	if ( $parts[0] !== 'sb-ns' ) {
		return $result;
	}
	list( $ns, $version ) = $parts;
	// ruleid: wp-rest-gate-case
	if ( in_array( $ns . '/' . $version, SB_GATED_NAMESPACES, true ) && ! sb_secret_ok( $request ) ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	return $result;
}, 10, 3 );

// preg_match without i, a pattern concatenated from a constant
add_filter( 'rest_request_before_callbacks', function ( $response, $handler, $request ) {
	// ruleid: wp-rest-gate-case
	if ( preg_match( '#^/sb-ns/v1/#', $request->get_route() ) && ! sb_secret_ok( $request ) ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	// ruleid: wp-rest-gate-case
	if ( 1 === preg_match( '#^/' . preg_quote( SB_NS, '#' ) . '/#', $request->get_route() ) && ! sb_secret_ok( $request ) ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	return $response;
}, 10, 3 );

// The ?rest_route= form and REQUEST_URI, on rest_authentication_errors (no $request to hand)
add_filter( 'rest_authentication_errors', function ( $result ) {
	$route = isset( $_GET['rest_route'] ) ? sanitize_text_field( wp_unslash( $_GET['rest_route'] ) ) : '';
	// ruleid: wp-rest-gate-case
	if ( str_starts_with( $route, '/sb-private/' ) && ! is_user_logged_in() ) {
		return new WP_Error( 'rest_forbidden', 'Login required.', array( 'status' => 401 ) );
	}
	$uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
	// ruleid: wp-rest-gate-case
	if ( false !== strpos( $uri, '/wp-json/sb-private/' ) && ! is_user_logged_in() ) {
		return new WP_Error( 'rest_forbidden', 'Login required.', array( 'status' => 401 ) );
	}
	return $result;
} );

// switch and match on the route; a direction that cannot be read (a ternary, an assignment)
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	$route = $request->get_route();
	// ruleid: wp-rest-gate-case
	switch ( $route ) {
		case '/sb-ns/v1/submit':
			return sb_secret_ok( $request ) ? $result : new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	// ruleid: wp-rest-gate-case
	$gated = match ( $route ) { '/sb-ns/v1/a', '/sb-ns/v1/b' => true, default => false };
	// ruleid: wp-rest-gate-case
	$is_ours = str_starts_with( $route, '/sb-ns/' );
	// ruleid: wp-rest-gate-case
	return str_ends_with( $route, '/export' ) && ! sb_secret_ok( $request ) ? new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) ) : $result;
}, 10, 3 );

// An arrow function; a first-class callable; a namespaced string callback
// ruleid: wp-rest-gate-case
add_filter( 'rest_pre_dispatch', fn ( $result, $server, $request ) => str_contains( $request->get_route(), '/sb-ns/' ) && ! sb_secret_ok( $request ) ? new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) ) : $result, 10, 3 );
class SB_Callable_Gate {
	public function __construct() {
		add_filter( 'rest_pre_dispatch', $this->gate( ... ), 10, 3 );
		add_filter( 'rest_request_before_callbacks', __NAMESPACE__ . '\\sb_namespaced_gate', 10, 3 );
	}
	public function gate( $result, $server, $request ) {
		// ruleid: wp-rest-gate-case
		if ( $request->get_route() === '/sb-ns/v1/export' && ! sb_secret_ok( $request ) ) {
			return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
		}
		return $result;
	}
}
function sb_namespaced_gate( $response, $handler, $request ) {
	// ruleid: wp-rest-gate-case
	if ( ! str_starts_with( $request->get_route(), '/sb-ns/v2/' ) ) {
		return $response;
	}
	return sb_secret_ok( $request ) ? $response : new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
}

// One level of helper: the comparison lives in a function the gate calls
add_filter( 'rest_pre_dispatch', array( 'SB_Helper_Gate', 'gate' ), 10, 3 );
class SB_Helper_Gate {
	public static function gate( $result, $server, $request ) {
		if ( ! self::is_ours( $request->get_route() ) ) {
			return $result;
		}
		if ( self::needs_secret( $request ) && ! sb_secret_ok( $request ) ) {
			return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
		}
		return $result;
	}
	private static function is_ours( $route ) {
		// ruleid: wp-rest-gate-case
		return str_starts_with( $route, '/sb-helper/v1/' );
	}
	private static function needs_secret( $request ) {
		// ruleid: wp-rest-gate-case
		if ( str_starts_with( $request->get_route(), '/sb-helper/v1/private/' ) ) {
			return true;
		}
		return false;
	}
}

// A lower-cased route against a literal with capitals: it never matches, so the gate never applies
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	$route = strtolower( $request->get_route() );
	// ruleid: wp-rest-gate-case
	if ( str_starts_with( $route, '/SB-NS/v1/' ) && ! sb_secret_ok( $request ) ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	return $result;
}, 10, 3 );

// A WordPress Plugin Boilerplate loader registration
class SB_Plugin {
	public function define_hooks() {
		$this->loader->add_filter( 'rest_pre_dispatch', $this->public, 'wppb_gate', 10, 3 );
	}
}
class SB_Public {
	public function wppb_gate( $result, $server, $request ) {
		// ruleid: wp-rest-gate-case
		if ( str_starts_with( $request->get_route(), '/sb-wppb/' ) && ! sb_secret_ok( $request ) ) {
			return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
		}
		return $result;
	}
}

// A pragma with no reason waives nothing
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	// lint-allow-wp-rest-gate-case:
	// ruleid: wp-rest-gate-case
	if ( str_starts_with( $request->get_route(), '/sb-bare/' ) && ! sb_secret_ok( $request ) ) {
		return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}
	return $result;
}, 10, 3 );
