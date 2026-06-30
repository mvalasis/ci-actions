<?php
// security-baseline WP/PHP rule self-test fixture (semgrep --test).
// Each function isolates ONE rule so the per-line annotations stay unambiguous.
// Run: semgrep --test --config rules/wp-php.yaml rules/selftest/wp-php.php

// ---- wp-sql-unprepared ----
function sb_sql_bad($id) {
	global $wpdb;
	// ruleid: wp-sql-unprepared
	return $wpdb->get_row("SELECT * FROM {$wpdb->prefix}eb_users WHERE id = $id");
}
function sb_sql_ok($id) {
	global $wpdb;
	// ok: wp-sql-unprepared
	return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}eb_users WHERE id = %d", $id));
}

// ---- wp-nonce-missing (request data into a write; has cap, no nonce => only this fires) ----
function sb_nonce_bad() {
	global $wpdb;
	if (!current_user_can('manage_options')) wp_die('no');
	// ruleid: wp-nonce-missing
	$wpdb->update('eb_partners', array('name' => $_POST['name']), array('id' => 1));
}
function sb_nonce_ok() {
	global $wpdb;
	check_admin_referer('eb_save');
	if (!current_user_can('manage_options')) wp_die('no');
	// ok: wp-nonce-missing
	$wpdb->update('eb_partners', array('name' => sanitize_text_field($_POST['name'])), array('id' => 1));
}

// ---- wp-cap-missing (request data into a write; has nonce, no cap => only this fires) ----
function sb_cap_bad() {
	global $wpdb;
	check_admin_referer('eb_act');
	// ruleid: wp-cap-missing
	$wpdb->delete('eb_log', array('id' => $_POST['id']));
}
function sb_cap_ok() {
	global $wpdb;
	check_admin_referer('eb_act');
	if (!current_user_can('manage_woocommerce')) wp_die('no');
	// ok: wp-cap-missing
	$wpdb->delete('eb_log', array('id' => absint($_POST['id'])));
}

// ---- wp-unserialize-user-input ----
function sb_unser_bad() {
	// ruleid: wp-unserialize-user-input
	return unserialize($_COOKIE['eb_prefs']);
}
function sb_unser_ok() {
	// ok: wp-unserialize-user-input
	return unserialize($_COOKIE['eb_prefs'], array('allowed_classes' => false));
}

// ---- wp-file-include-user-input ----
function sb_lfi_bad() {
	// ruleid: wp-file-include-user-input
	include(ABSPATH . 'reports/' . $_GET['tpl'] . '.php');
}
function sb_lfi_ok() {
	// ok: wp-file-include-user-input
	include(ABSPATH . 'reports/' . basename($_GET['tpl']) . '.php');
}

// ---- wp-rest-exception-detail (mirrors real hlek rest-payment.php) ----
function sb_rest_bad($e) {
	// ruleid: wp-rest-exception-detail
	return new \WP_REST_Response(array(
		'error'   => 'internal',
		'message' => $e->getMessage(),
	), 500);
}
function sb_rest_ok($e) {
	error_log('[plugin] fatal: ' . $e->getMessage());
	// ok: wp-rest-exception-detail
	return new \WP_REST_Response(array('error' => 'internal'), 500);
}
// AJAX leak — the gap found 2026-06-29 (EPN custom plugins leak via exactly this).
function sb_ajax_msg_bad($e) {
	// ruleid: wp-rest-exception-detail
	wp_send_json_error($e->getMessage());
}
function sb_ajax_arr_bad($e) {
	// ruleid: wp-rest-exception-detail
	wp_send_json_error(array('line' => $e->getLine(), 'file' => $e->getFile()), 500);
}
function sb_ajax_trace_bad($e) {
	// ruleid: wp-rest-exception-detail
	wp_send_json(array('ok' => false, 'detail' => $e->getTraceAsString()));
}
function sb_ajax_success_bad($e) {
	// ruleid: wp-rest-exception-detail
	wp_send_json_success(array('debug' => $e->getMessage()));
}
// wp_die() leak — the frontend/admin sink that terminates with raw exception detail.
function sb_die_msg_bad($e) {
	// ruleid: wp-rest-exception-detail
	wp_die($e->getMessage());
}
function sb_die_trace_bad($e) {
	// ruleid: wp-rest-exception-detail
	wp_die($e->getTraceAsString(), 'Fatal error', array('response' => 500));
}
function sb_ajax_ok($e) {
	error_log('[plugin] fatal: ' . $e->getMessage());
	// ok: wp-rest-exception-detail
	wp_send_json_error('internal error');
}
function sb_die_ok($e) {
	error_log('[plugin] fatal: ' . $e->getMessage());
	// ok: wp-rest-exception-detail
	wp_die('An unexpected error occurred. Please try again.');
}

// ---- wp-rest-wp-error-detail (T2 advisory — the hlek rest-categories WP_Error case) ----
function sb_wperror_bad($wpe) {
	// ruleid: wp-rest-wp-error-detail
	wp_send_json_error($wpe->get_error_message());
}
function sb_wperror_rest_bad($wpe) {
	// ruleid: wp-rest-wp-error-detail
	return new \WP_REST_Response(array('message' => $wpe->get_error_message()), 500);
}
function sb_wperror_success_bad($wpe) {
	// ruleid: wp-rest-wp-error-detail
	wp_send_json_success(array('note' => $wpe->get_error_message()));
}
function sb_wperror_die_bad($wpe) {
	// ruleid: wp-rest-wp-error-detail
	wp_die($wpe->get_error_message());
}
function sb_wperror_ok() {
	// ok: wp-rest-wp-error-detail
	wp_send_json_error('plain curated string');
}

// ---- wp-weak-crypto-signing (signing var fires; cache-key does not) ----
function sb_crypto_bad($payload, $secret) {
	// ruleid: wp-weak-crypto-signing
	$signature = md5($payload . $secret);
	return $signature;
}
function sb_crypto_ok($ip) {
	// ok: wp-weak-crypto-signing
	$cache_key = md5($ip);
	return $cache_key;
}

// ---- wp-turnstile-test-sitekey ----
function sb_turnstile_bad() {
	// ruleid: wp-turnstile-test-sitekey
	$sitekey = defined('TURNSTILE_KEY') ? TURNSTILE_KEY : '0x0000000000000000000000';
	return $sitekey;
}
function sb_turnstile_ok() {
	// ok: wp-turnstile-test-sitekey
	$sitekey = defined('TURNSTILE_KEY') ? TURNSTILE_KEY : '';
	return $sitekey;
}

// ---- wp-unescaped-output (T2 advisory) ----
function sb_xss_bad() {
	// ruleid: wp-unescaped-output
	echo $_GET['q'];
}
function sb_xss_ok() {
	// ok: wp-unescaped-output
	echo esc_html($_GET['q']);
}
