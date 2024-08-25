<?php

if (!defined('BOOTSTRAP')) { die('Access denied'); }
use Tygh\Registry;

if ($mode == 'notify') {
	$data = json_decode(file_get_contents('php://input'), true);
	if (is_array($data)) {
		$data = array_merge($data, $_GET);
	} else {
		$data = $_GET;
	}
	$addonParams = Registry::get('addons.ee_sberQRSBP');
	if (isset($data['operationId']) && $data['operationId'] && isset($data['authCode']) && $data['authCode']) {
		$json_data = json_decode(db_get_field('SELECT partner_order_number FROM ?:orders WHERE order_id = ?i', $data['partnerOrderNumber']), true);
		$json_data['operation_id'] = $data['operationId'];
		$json_data['auth_code'] = $data['authCode'];
		db_query('UPDATE ?:orders SET partner_order_number = ?s WHERE order_id = ?i', json_encode($json_data), $data['partnerOrderNumber']);
	}
	if ($addonParams['logs'] == 'Y') {
		$path_logs = Registry::get('config.dir.addons') . 'ee_sberQRSBP/logs';
		file_put_contents($path_logs . '/' . date('d.m.Y') . '_notify.txt', var_export($data, true), FILE_APPEND);
	}
}
