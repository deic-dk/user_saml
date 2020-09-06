$(document).ready(function() {
	$('#samlSettings').tabs();
	$('#samlSettings').removeClass('ui-widget');
	$('#samlSettings').removeClass('ui-widget-content');
	$('#samlSettings').removeClass('ui-corner-all');
	$('#samlSettings ul').removeClass('ui-widget');
	$('#samlSettings ul').removeClass('ui-widget-header');
	$('#samlSettings ul').removeClass('ui-corner-all');

	$('#save_saml_settings').click(function(ev){
		$.ajax({
			type: "POST",
			url: OC.webroot+'/apps/user_saml/ajax/save_settings.php?admin_login=1&requesttoken='+oc_requesttoken,
			//url: OC.filePath('user_saml', 'ajax', 'save_settings.php?admin_login=1&requesttoken='+oc_requesttoken),
			data: $('form#saml').serialize(),
			success: function(data){
				OC.msg.finishedSaving('#samlMsg', {status: 'success', data: {message: "SAML settings saved"}});
				}
			});
		});
	});
