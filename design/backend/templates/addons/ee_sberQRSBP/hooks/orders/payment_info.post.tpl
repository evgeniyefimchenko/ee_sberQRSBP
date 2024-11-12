{if $order_info.payment_method.payment_id == $addons.ee_sberQRSBP.payment_id}	
	{if !$order_info.partner_order_number}	
		{$orderParams.rq_tm = $smarty.now|date_format:"%Y-%m-%dT%H:%M:%SZ"}
		{$orderParams.order_number = $order_info.order_id}
		{$orderParams.order_create_date = $order_info.updated_at|date_format:"%Y-%m-%dT%H:%M:%SZ"}
		{$orderParams.order_sum = $order_info.total}
		{$orderParams.description = $order_info.notes|truncate:50}        
		{assign var="params" value=""}
		{foreach from=$orderParams key=key item=value}
			{assign var="encoded_value" value=$value|urlencode}
			{assign var="params" value=$params|cat:"&`$key`=`$encoded_value`"}
		{/foreach}
		<a href="//{$config.https_host}/{$config.admin_index}?dispatch=ee_sberQRSBP.create{$params}" class="btn btn-primary">Генерация QR</a>		
	{else}
		{$decode = $order_info.partner_order_number|json_decode:true}
		<a href="{$decode.order_form_url}" class="btn btn-primary" target="_BLANK">Получить QR CODE</a>
		<button class="btn btn-secondary" type="button" onclick="copyToClipboard('{$decode.order_form_url}')">Скопировать ссылку</button>
		{$status = $decode.order_id|fn_ee_sberQRSBP_checkOrderStatus:$order_info.order_id}
		<h5 id="order-status">Статус: {$status}</h5>
		{if $status == 'ОПЛАЧЕН'}
			{if !$decode.operation_id || !$decode.auth_code}
				<span style="color: red;">Отсутствует operation_id или auth_code возврат невозможен!</span>			
			{else}
				<a href="//{$config.https_host}/{$config.admin_index}?dispatch=ee_sberQRSBP.refund&order_id={$decode.order_id}&operation_id={$decode.operation_id}&sum={$order_info.total}&auth_code={$decode.auth_code}"
				class="btn btn-primary" onclick="return confirm('Вы уверены, что хотите оформить возврат?')">Оформить возврат</a>
			{/if}
		{/if}
		{if $status == 'СОЗДАН'}
			{if !$decode.operation_id}
				<span style="color: red;">Отсутствует operation_id возврат невозможен!</span>
			{else}
				<a href="//{$config.https_host}/{$config.admin_index}?dispatch=ee_sberQRSBP.revocation&order_id={$decode.order_id}&operation_id={$decode.operation_id}"
				class="btn btn-primary" onclick="return confirm('Вы уверены, что хотите оформить возврат?')">Оформить возврат</a>
			{/if}
		{/if}
		<script>
			function copyToClipboard(text) {
				var textarea = document.createElement("textarea");
				textarea.value = text;
				document.body.appendChild(textarea);
				textarea.select();
				document.execCommand("copy");
				document.body.removeChild(textarea);
				alert('Ссылка скопирована!');
			}			
			(function(_, $) {
				function updateOrderStatus() {
					var params = {
						data: {
							dispatch: 'ee_sberQRSBP.status',
							order_id: '{$order_info.order_id}',
							sberID: '{$decode.order_id}'
						},
						method: 'get',
						callback: function(response) {
							$('#order-status').text('Статус: ' + response.status);
						},
						hidden: true,
						caching: false							
					};
					$.ceAjax('request', _.current_location + '/{$config.admin_index}', params);
				}
				setInterval(updateOrderStatus, 300000);
			}(Tygh, Tygh.$));
		</script>			
	{/if}
{/if}
