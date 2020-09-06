<?php

//require_once __DIR__ . '/../../../lib/base.php';

OC_Log::write('user_saml',"SESSION: ".serialize(\OC::$session), OC_Log::WARN);

OC_Util::checkAdminUser();
//OCP\JSON::checkLoggedIn();

$params = array('saml_ssp_path', 'saml_sp_source', 'saml_force_saml_login', 'saml_autocreate',
		'saml_update_user_data', 'saml_protected_groups', 'saml_default_group', 'saml_username_mapping',
		'saml_email_mapping', 'saml_quota_mapping', 'saml_default_quota', 'saml_displayname_mapping',
		'saml_group_mapping', 'saml_affiliation_mapping', 'saml_group_admin');

// CSRF check
//OCP\JSON::callCheck();

OC_Log::write('user_saml',"Setting SAML parameters: ".serialize($_POST), OC_Log::WARN);

foreach($params as $param) {
	if (isset($_POST[$param])) {
		OCP\Config::setAppValue('user_saml', $param, $_POST[$param]);
	}
	elseif ('saml_force_saml_login' == $param) {
		OCP\Config::setAppValue('user_saml', $param, 0);
	}
	elseif ('saml_autocreate' == $param) {
		// unchecked checkboxes are not included in the post paramters
		OCP\Config::setAppValue('user_saml', $param, 0);
	}
	elseif ('saml_update_user_data' == $param) {
		OCP\Config::setAppValue('user_saml', $param, 0);
	}
}

\OC_JSON::success();
