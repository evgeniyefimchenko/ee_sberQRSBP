<?php

if (!defined('BOOTSTRAP')) { die('Access denied'); }

use Tygh\Registry;

if (strpos($_SERVER['HTTP_REFERER'], '?dispatch=orders.details&order_id=') && !fn_ee_sberQRSBP_is_ajax_request()) {
	if ($mode == 'create') {
        $requiredParams = [
            'rq_tm' => $_GET['rq_tm'],
            'order_number' => $_GET['order_number'],
            'order_create_date' => $_GET['order_create_date'],
            'order_sum' => $_GET['order_sum'],
            'description' => $_GET['description']
        ];
        $allParamsExist = array_reduce(array_keys($requiredParams), function ($carry, $key) {
            return $carry && isset($_GET[$key]);
        }, true);
        if ($allParamsExist) {
            $result = fn_ee_sberQRSBP_createSberPayQR($requiredParams);
			if ($result) fn_set_notification('N', __('notice'), 'Успешно');
        } else {
			fn_set_notification('E', __('error'), 'Отсутствует один или несколько обязательных параметров!');
        }
    } else if ($mode == 'refund') {
		fn_ee_sberQRSBP_refundOrder($_GET['order_id'], $_GET['operation_id'], $_GET['sum'], $_GET['auth_code']);
	} else if ($mode == 'revocation') {
		fn_ee_sberQRSBP_revocationOrder($_GET['order_id']);
	}
	return [CONTROLLER_STATUS_OK, $_SERVER['HTTP_REFERER']];
}

if (fn_ee_sberQRSBP_is_ajax_request() && fn_ee_sberQRSBP_is_request_from_current_site() && $mode == 'status') {
	Tygh::$app['ajax']->assign('status', fn_ee_sberQRSBP_checkOrderStatus($_GET['sberID'], $_GET['order_id']));
	die;
} else {
	return [CONTROLLER_STATUS_OK, $_SERVER['HTTP_REFERER']];
}

header("HTTP/1.0 404 Not Found");
die;
