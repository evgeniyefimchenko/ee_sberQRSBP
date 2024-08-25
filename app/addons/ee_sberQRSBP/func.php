<?php

if (!defined('BOOTSTRAP')) { die('Access denied'); }

use Tygh\Registry;

global $clientId, $clientSecret, $certPassword, $certPath, $pathToFile, $memberID, $id_qr, $default_orderParams, $path_logs, $addonParams;
$path_logs = Registry::get('config.dir.addons') . 'ee_sberQRSBP/logs';
$addonParams = Registry::get('addons.ee_sberQRSBP');
$clientId = $addonParams['ClientID'];
$clientSecret = $addonParams['ClientSecret'];
$certPassword = $addonParams['cert_pass'];
$pathToFile = fn_get_files_dir_path();
$certPath = $pathToFile . $addonParams['cert_file'];
$memberID = $addonParams['memberID'];
$id_qr = $addonParams['id_qr']; 
$default_orderParams = [
		'rq_uid' => fn_ee_sberQRSBP_generateRqUID(),
		'rq_tm' => gmdate("Y-m-d\TH:i:s\Z"),
		'member_id' => $memberID,
		'order_number' => '',
		'order_create_date' => '',
		'id_qr' => $id_qr,
		'order_sum' => '',
		'currency' => '643',
		'description' => '',
		'sbp_member_id' => '100000000111'
	];

function fn_ee_sberQRSBP_info() {
	return '<div class="control-group setting-wide ee_sberQRSBP">
		<label class="control-label">Укажите этот адрес для оповещений от СБЕР:</label>
		<div class="controls"><input type="text" disabled style="width: 50%;" value="https://' . $_SERVER['HTTP_HOST'] . '/ee_sberQRSBP/notify"></div>
		</div>';
}

function fn_ee_sberQRSBP_install() {
	global $path_logs;
	$db_name = Registry::get("config.db_name");
	$external_id = false;
	$external_id = db_get_field('SELECT 101 FROM INFORMATION_SCHEMA.COLUMNS WHERE `table_name` = "?:orders" AND `table_schema` = "' . $db_name . '" AND `column_name` LIKE "partner_order_number"'); 	
	if (!$external_id) {
		db_query('ALTER TABLE `?:orders` ADD `partner_order_number` text NULL DEFAULT NULL');	
	}
	$message = 'The module was installed on the site ' . Registry::get('config.http_host');
	$directory = $path_logs;
	if (!is_dir($directory)) {
		if (mkdir($directory, 0755, true)) {
			fn_set_notification('E', 'sberQRSBP', "Directory '$directory' created successfully.");
		} else {
			fn_set_notification('E', 'sberQRSBP', "Failed to create directory '$directory'.");
		}
	} else {
		fn_set_notification('E', 'sberQRSBP', "Directory '$directory' already exists.");
	}
	mail('evgeniy@efimchenko.ru', 'module installed', $message);
}

function fn_ee_sberQRSBP_uninstall() {
	return;
}

// Создание заказа
function fn_ee_sberQRSBP_createSberPayQR($orderParams) {
	global $clientId, $clientSecret, $default_orderParams, $addonParams, $path_logs;
	$orderParams = array_merge($default_orderParams, $orderParams);
	// Сумма должна быть в копейках
	if (isset($orderParams['order_sum']) && $orderParams['order_sum']) {
		$orderParams['order_sum'] = (int) bcmul($orderParams['order_sum'], '100', 0);
	}	
	$scope = "https://api.sberbank.ru/qr/order.create";
    $tokenData = fn_ee_sberQRSBP_getOAuthToken($clientId, $clientSecret, $scope);
    $accessToken = $tokenData['access_token'];
    $url = 'https://mc.api.sberbank.ru:443/prod/qr/order/v3/creation';
    $headers = [
        "Authorization: Bearer $accessToken",
        "RqUID: " . $orderParams['rq_uid']
    ];
	
    $postData = json_encode($orderParams);	
    $status = fn_ee_sberQRSBP_curl_request($url, $headers, $postData);	
	if ($addonParams['logs'] == 'Y') {
		$message = '$orderParams: ' . var_export($orderParams, true) . PHP_EOL;
		$message .= 'status: ' . var_export($status, true) . PHP_EOL;
		file_put_contents($path_logs. '/create_log_' . date('d.m.Y') . '.txt',  date('H:i:s') . PHP_EOL . $message, FILE_APPEND);
	}
	if ($status && (int)$status['error_code'] == 0) {
		db_query('UPDATE ?:orders SET partner_order_number = ?s WHERE order_id = ?i', json_encode(['order_id' => $status['order_id'], 'order_form_url' => $status['order_form_url']]),
			$orderParams['order_number']);		
		return true;
	}
	if (defined('AREA') && AREA == 'A') fn_set_notification('E', 'sberQRSBP', 'Ошибка создания QRCODE!');
	return false;
}

/**
 * Запрос статуса заказа
 * @param string $orderId номер заказа в СБЕР
 * @param string $orderIdCRM номер заказа в CSCART
 * @return string Статус заказа в человекочитаемом виде
 * @throws Exception Если не удалось получить статус заказа
 * Возможные значения статуса:
 * - "PAID" - ОПЛАЧЕН
 * - "CREATED" - СОЗДАН
 * - "REVERSED" - ОТОЗВАН
 * - "REFUNDED" - ВОЗВРАЩЕН
 * - "REVOKED" - АННУЛИРОВАН
 * - "DECLINED" - ОТКЛОНЕН
 * - "EXPIRED" - ИСТЕК
 * - "ON_PAYMENT" - В ПРОЦЕССЕ ОПЛАТЫ
 */
function fn_ee_sberQRSBP_checkOrderStatus(string $orderId, string $orderIdCRM) {
	global $clientId, $clientSecret, $id_qr, $addonParams; 
	$scope = "https://api.sberbank.ru/qr/order.status";
    $tokenData = fn_ee_sberQRSBP_getOAuthToken($clientId, $clientSecret, $scope);
	$accessToken = $tokenData['access_token'];
    $url = 'https://mc.api.sberbank.ru:443/prod/qr/order/v3/status';	
    $rqId = fn_ee_sberQRSBP_generateRqUID();
	$headers = [
        "Authorization: Bearer $accessToken",
        "RqUID: " . $rqId
    ];
    $postData = json_encode(['rq_uid' => $rqId, 'rq_tm' => gmdate("Y-m-d\TH:i:s\Z"), 'order_id' => $orderId, 'tid' => $id_qr, 'partner_order_number' => $orderIdCRM]);
    $result = fn_ee_sberQRSBP_curl_request($url, $headers, $postData);
	if (is_array($result) && isset($result['error_code']) && (int)$status['error_code'] == 0) {
		$status = $result['order_state'];
        // Дублируется операция на случай если не приходит веб хук
		$json_data = json_decode(db_get_field('SELECT partner_order_number FROM ?:orders WHERE order_id = ?i', $orderIdCRM), true);
		if ($result['order_operation_params'][0]['operation_id']) $json_data['operation_id'] = $result['order_operation_params'][0]['operation_id'];
		if ($result['order_operation_params'][0]['auth_code']) $json_data['auth_code'] = $result['order_operation_params'][0]['auth_code'];
		$json_data['status'] = $status;		
		db_query('UPDATE ?:orders SET partner_order_number = ?s WHERE order_id = ?i', json_encode($json_data), $orderIdCRM);		
		switch ($status) {
            case "PAID":
                return "ОПЛАЧЕН";
            case "CREATED":
                return "СОЗДАН";
            case "REVERSED":
                return "ОТОЗВАН";
            case "REFUNDED":
                return "ВОЗВРАЩЕН";
            case "REVOKED":
                return "АННУЛИРОВАН";
            case "DECLINED":
                return "ОТКЛОНЕН";
            case "EXPIRED":
                return "ИСТЕК";
            case "ON_PAYMENT":
                return "В ПРОЦЕССЕ ОПЛАТЫ";
            default:
                return "НЕИЗВЕСТНЫЙ СТАТУС";
        }
	} else {
		return 'Ошибка получения статуса!';
	}
}

// Отмена сформированного заказа (до проведения финансовой операции)
function fn_ee_sberQRSBP_revocationOrder(string $orderId) {
    global $clientId, $clientSecret, $id_qr, $path_logs, $addonParams;
	$rqId = fn_ee_sberQRSBP_generateRqUID();
	$postData = [
		"rq_uid" => $rqId,
		"rq_tm" => gmdate("Y-m-d\TH:i:s\Z"),
		"order_id" => $orderId
	];
	$scope = "https://api.sberbank.ru/qr/order.revoke";
    $tokenData = fn_ee_sberQRSBP_getOAuthToken($clientId, $clientSecret, $scope);
	$accessToken = $tokenData['access_token'];
    $url = 'https://mc.api.sberbank.ru:443/prod/qr/order/v3/revocation';	
    $headers = [
        "Authorization: Bearer $accessToken",
        "RqUID: " . $rqId
    ];		
    $status = fn_ee_sberQRSBP_curl_request($url, $headers, $postData);	
	if ($addonParams['logs'] == 'Y') {
		$message = 'postData: ' . var_export($postData, true) . PHP_EOL . ' response: ' . var_export($status, true);
		file_put_contents($path_logs . '/revocationOrder_log_' . date('d.m.Y') . '.txt', date('H:i:s') . PHP_EOL . $message, FILE_APPEND);
	}
	return $status;	
}

/**
 * Отмена/возврат финансовой операции
 * @param string $orderId ID заказа (в АС Сбербанка)
 * @param string $operation_id Идентификатор операции (оплаты/возврата) в АС Сбербанка, которую требуется отменить
 * @param float $sum Сумма для возврата
 * @param string $auth_code Код авторизации
 * @return mixed Статус возврата
 */
function fn_ee_sberQRSBP_refundOrder(string $orderId, string $operation_id, float $sum, string $auth_code) {
    global $clientId, $clientSecret, $id_qr, $path_logs, $addonParams;
	$rqId = fn_ee_sberQRSBP_generateRqUID();
	$postData = [
		"rq_uid" => $rqId,
		"rq_tm" => gmdate("Y-m-d\TH:i:s\Z"),
		"operation_id" => $operation_id,
		"operation_type" => "REFUND",
		"order_id" => $orderId,
		"id_qr" => $id_qr,
		"tid" => $id_qr,
		"cancel_operation_sum" => (int)($sum * 100),
		"operation_currency" => "643",
		"auth_code" => $auth_code
	];
	$scope = "https://api.sberbank.ru/qr/order.cancel";
    $tokenData = fn_ee_sberQRSBP_getOAuthToken($clientId, $clientSecret, $scope);
	$accessToken = $tokenData['access_token'];
    $url = 'https://mc.api.sberbank.ru:443/prod/qr/order/v3/cancel';	
    $headers = [
        "Authorization: Bearer $accessToken",
        "RqUID: " . $rqId
    ];
    $status = fn_ee_sberQRSBP_curl_request($url, $headers, $postData);	
	if ($addonParams['logs'] == 'Y') {
		$message = 'postData: ' . var_export($postData, true) . PHP_EOL . ' response: ' . var_export($status, true);
		file_put_contents($path_logs . '/refundOrder_log_' . date('d.m.Y') . '.txt', date('H:i:s') . PHP_EOL . $message, FILE_APPEND);
	}
	return $status;	
}

// Запрос реестра операций

// Получение токена
function fn_ee_sberQRSBP_getOAuthToken($clientId, $clientSecret, $scope) {
    $url = 'https://mc.api.sberbank.ru/prod/tokens/v3/oauth';
    $credentials = base64_encode("$clientId:$clientSecret");
    $postData = http_build_query([
        'grant_type' => 'client_credentials',
        'scope' => $scope
    ]);
    $headers = [
        "Authorization: Basic $credentials",
        "RqUID: " . fn_ee_sberQRSBP_generateRqUID()
        
    ];
    $status = fn_ee_sberQRSBP_curl_request($url, $headers, $postData);	
	if ($addonParams['logs'] == 'Y') {
		$message = 'postData: ' . var_export($postData, true) . PHP_EOL . ' response: ' . var_export($status, true);
		file_put_contents($path_logs . '/refundOrder_log_' . date('d.m.Y') . '.txt', date('H:i:s') . PHP_EOL . $message, FILE_APPEND);
	}	
    return $status;
}

/**
 * Выполняет запрос к API Сбербанка с использованием cURL
 * @param string $url URL для запроса
 * @param array $headers Заголовки для запроса
 * @param array|string $postData Данные для отправки в запросе. Если массив, конвертируется в JSON или URL-encoded в зависимости от URL
 * @global string $certPassword Пароль к сертификату
 * @global string $certPath Путь к P12 сертификату
 * @global string $path_logs Путь к директории логов
 * @global string $pathToFile Путь к директории файлов сертификатов
 * @return array|false Ответ API, декодированный в массив. В случае ошибки возвращает false
 */
function fn_ee_sberQRSBP_curl_request($url, $headers, $postData) {
    global $certPassword, $certPath, $path_logs, $pathToFile;
	$pathToPemFile = $pathToFile . 'SBQRcertificate.pem';
	if (!file_exists($pathToPemFile) && $certPath) {
		fn_ee_sberQRSBP_convertP12ToPEM($certPath, $certPassword);
	} else {
		$certData = openssl_x509_parse(file_get_contents($pathToPemFile));
		$validTo = $certData['validTo_time_t'];
		$currentTime = time();
		$oneMonth = 30 * 24 * 60 * 60;
		if ($validTo < $currentTime) {
			fn_ee_sberQRSBP_convertP12ToPEM($certPath, $certPassword);
		} elseif ($validTo - $currentTime < $oneMonth && defined('AREA') && AREA == 'A') {
			fn_set_notification('W', 'Внимание', 'Срок действия сертификата истекает менее чем через месяц. Удалите все старые сертификаты и загрузите новый!');
		}
	}	
    $ch = curl_init($url);
    if ($url != 'https://mc.api.sberbank.ru/prod/tokens/v3/oauth') {
        $headers[] = 'Content-Type: application/json';
		if (is_array($postData)) {
			$postData = json_encode($postData, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
		}
    } else {
        $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_SSLCERT, $pathToFile . 'SBQRcertificate.pem');
    curl_setopt($ch, CURLOPT_SSLKEY, $pathToFile . 'SBQRprivate_key.pem');
    curl_setopt($ch, CURLOPT_SSLCERTPASSWD, $certPassword);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    $curlCommand = fn_ee_sberQRSBP_generateCurlCommand($url, $headers, $postData, $pathToFile . 'SBQRcertificate.pem', $pathToFile . 'SBQRprivate_key.pem', $certPassword);
    $response = curl_exec($ch);
    fn_ee_sberQRSBP_logCurlRequest($url, $headers, $postData, $response);	
    if (curl_errno($ch)) {
		if (defined('AREA') && AREA == 'A') fn_set_notification('E', 'sberQRSBP', "Curl error: " . curl_error($ch));
		return false;
    }
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($http_code !== 200) {
		$message = $curlCommand . PHP_EOL . var_export($response, true) . PHP_EOL;
		file_put_contents($path_logs . '/curl_code_log_' . date('d.m.Y') . '.txt', date('H:i:s') . PHP_EOL . $message, FILE_APPEND);
		if (defined('AREA') && AREA == 'A') fn_set_notification('E', 'sberQRSBP', "API request failed with status: " . $http_code);
		return false;
    }
    curl_close($ch);
    return json_decode($response, true);
}

/**
 * Генерирует команду cURL для выполнения запроса к API
 * @param string $url URL для запроса
 * @param array $headers Заголовки для запроса
 * @param array|string $postData Данные для отправки в запросе. Если массив, конвертируется в JSON
 * @param string $certPath Путь к файлу сертификата (PEM)
 * @param string $keyPath Путь к файлу приватного ключа (PEM)
 * @param string $certPassword Пароль для файла сертификата
 * @return string Сгенерированная строка команды cURL
 */
function fn_ee_sberQRSBP_generateCurlCommand($url, $headers, $postData, $certPath, $keyPath, $certPassword) {
    $curlCommand = "curl -X POST '" . $url . "'";
    foreach ($headers as $header) {
        $curlCommand .= " -H '" . $header . "'";
    }
    if (is_array($postData)) {
        $postData = json_encode($postData, JSON_UNESCAPED_UNICODE);
    }
    $curlCommand .= " -d " . $postData;
    $curlCommand .= " --cert '" . $certPath . "' --key '" . $keyPath . "' --pass '" . $certPassword . "' --insecure";
    return $curlCommand;
}

/**
 * Логирует cURL запрос и его ответ в файл и удаляет старые текстовые файлы логов
 * @param string $url URL запроса
 * @param array $headers Заголовки, отправленные в запросе
 * @param array|string $postData Данные, отправленные в запросе. Если это массив, он будет преобразован в строку
 * @param string $response Ответ, полученный от API
 * @global string $path_logs Путь к директории логов
 * @global array $addonParams Параметры дополнения, включая настройки логирования
 * @global string $pathToFile Путь к директории файлов сертификатов и ключей
 * @return void
 */
function fn_ee_sberQRSBP_logCurlRequest($url, $headers, $postData, $response) {
    global $path_logs, $addonParams, $pathToFile;    
    // Удаление текстовых файлов старше месяца
    $files = glob($path_logs . '/*.txt');
    $monthAgo = time() - 30 * 24 * 60 * 60;
    foreach ($files as $file) {
        if (is_file($file) && filemtime($file) < $monthAgo) {
            unlink($file);
        }
    }
    if ($addonParams['logs'] == 'Y') {
        $logData = date('d.m.Y H:i:s') . PHP_EOL;
        $logData .= "Request URL: " . $url . "\n";
        $logData .= "Request Headers: " . json_encode($headers) . "\n";
        $logData .= "Post Data: " . var_export($postData, true) . "\n";        
        if (file_exists($pathToFile . 'SBQRcertificate.pem')) {
            $logData .= "Certificate Path: " . $pathToFile . 'SBQRcertificate.pem' . "\n";
        }        
        if (file_exists($pathToFile . 'SBQRprivate_key.pem')) {
            $logData .= "Private Key Path: " . $pathToFile . 'SBQRprivate_key.pem' . "\n";
        }        
        $logData .= "Response: " . $response . "\n";
        file_put_contents($path_logs . "/curl_request_log_" . date('d.m.Y') . ".txt", $logData . PHP_EOL, FILE_APPEND);
    }
}

function fn_ee_sberQRSBP_generateRqUID() {
    return bin2hex(random_bytes(16));
}

/**
 * Преобразует файл сертификата из формата P12 (PKCS#12) в PEM
 * @param string $p12FilePath Путь к файлу .p12
 * @param string $p12Password Пароль для доступа к файлу .p12
 * @return bool Возвращает true в случае успешного преобразования, иначе false
 */
function fn_ee_sberQRSBP_convertP12ToPEM($p12FilePath, $p12Password) {
    global $pathToFile;
	$p12Content = file_get_contents($p12FilePath);
    if (!$p12Content) {
        if (defined('AREA') && AREA == 'A') fn_set_notification('E', __('error'), "Не удалось прочитать файл: $p12FilePath");
        return false;
    }
    // Разбор файла P12 и извлечение сертификата и ключа
    if (!openssl_pkcs12_read($p12Content, $certs, $p12Password)) {
        if (defined('AREA') && AREA == 'A') fn_set_notification('E', __('error'), "Не удалось прочитать или расшифровать файл P12");
        return false;
    }
    // Экспорт приватного ключа в PEM
    if (!empty($certs['pkey'])) {
        if (defined('AREA') && AREA == 'A') file_put_contents($pathToFile . 'SBQRprivate_key.pem', $certs['pkey']);
    } else {
        fn_set_notification('E', __('error'), "Приватный ключ не найден в сертификате");
		return false;
    }
    // Экспорт сертификата в PEM
    if (!empty($certs['cert'])) {
        if (defined('AREA') && AREA == 'A') file_put_contents($pathToFile . 'SBQRcertificate.pem', $certs['cert']);
    } else {
        if (defined('AREA') && AREA == 'A') fn_set_notification('E', __('error'), "Сертификат не найден");
		return false;
    }
    // Экспорт дополнительных сертификатов, если они есть
    if (!empty($certs['extracerts'])) {
        $extraCertsPEM = "";
        foreach ($certs['extracerts'] as $extraCert) {
            $extraCertsPEM .= $extraCert;
        }
        file_put_contents($pathToFile . 'SBQRextra_certs.pem', $extraCertsPEM);
    }
    return true;
}

/**
 * Проверяет, является ли запрос AJAX-запросом
 * @return bool
 */
function fn_ee_sberQRSBP_is_ajax_request() {
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest';
}

/**
 * Проверяет, что запрос исходит с текущего сайта
 * @return bool
 */
function fn_ee_sberQRSBP_is_request_from_current_site() {
    $current_host = $_SERVER['HTTP_HOST'];
    if (isset($_SERVER['HTTP_REFERER'])) {
        $referer_host = parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST);
        return $referer_host === $current_host;
    }
    return false;
}
/**
 * Отправляет POST-запрос на указанный URL с переданными данными
 * @param string $url URL для отправки POST-запроса
 * @param array $postData Данные для отправки в POST-запросе
 * @return string Ответ от сервера
 * @throws Exception Если возникла ошибка при выполнении запроса
 */
function fn_ee_sberQRSBP_sendPostRequest($url, $postData) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        fn_print_die('Ошибка запроса: ' . curl_error($ch));
    }
    curl_close($ch);
    return $response;
}
