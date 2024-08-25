<?php

if (!defined('BOOTSTRAP')) { die('Access denied'); }

function fn_settings_variants_addons_ee_sberQRSBP_payment_id() {
	$result = [];
	$data = fn_get_payments(['status' => 'A']);
	$result['0'] = 'Нет';
	foreach ($data as $k => $v) {
		$result[$k] = $v['payment'];
	}
	return $result;
}
