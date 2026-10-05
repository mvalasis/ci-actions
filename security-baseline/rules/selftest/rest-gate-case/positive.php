<?php
// wp-rest-gate-case fixture — POSITIVE: the two shapes this fleet shipped.
// `// ruleid: wp-rest-gate-case` marks the line below it as a finding; `// ok:` as silent.
// selftest.mjs grades this file under a synthetic path (rules/selftest/ is never graded by scan.mjs).

// Instance 2 (2026-10): the namespace built from a class constant, a mismatch let through.
class SB_Api_Rest {
	const NS = 'sb-api/v1';

	public static function register() {
		add_filter( 'rest_pre_dispatch', array( self::class, 'guard' ), 10, 3 );
	}

	public static function guard( $result, $server, $request ) {
		$route = (string) $request->get_route();
		$base  = '/' . self::NS;
		// ruleid: wp-rest-gate-case
		if ( $route !== $base && ! str_starts_with( $route, $base . '/' ) ) {
			return $result;
		}
		return self::allowed( $request ) ? $result : new WP_Error( 'sb_forbidden', 'Forbidden.', array( 'status' => 403 ) );
	}

	private static function allowed( WP_REST_Request $request ): bool {
		// ok: wp-rest-gate-case
		return current_user_can( 'edit_posts' ) || 'yes' === $request->get_header( 'x-sb-ok' );
	}
}

// The same gate with the namespace spelled as a literal.
add_filter( 'rest_pre_dispatch', 'sb_ns_literal_gate', 10, 3 );
function sb_ns_literal_gate( $result, $server, $request ) {
	// ruleid: wp-rest-gate-case
	if ( ! str_starts_with( $request->get_route(), '/sb-ns/v1/' ) ) {
		return $result;
	}
	return sb_secret_ok( $request ) ? $result : new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
}

// Instance 1 (a CF7 proxy gate): strpos === 0 on the route, the gate applied on a match.
add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	// ruleid: wp-rest-gate-case
	if ( 0 === strpos( $request->get_route(), '/contact-form-7/' ) && ! sb_cf7_proxy_ok() ) {
		return new WP_Error( 'proxy_required', 'Forbidden.', array( 'status' => 403 ) );
	}
	return $result;
}, 10, 3 );
