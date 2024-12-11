<?php

OCP\JSON::checkAppEnabled('user_saml');
OCP\JSON::checkAppEnabled('files_sharding');
OC_JSON::checkLoggedIn();

$username = OC_User::getUser();
$password = isset($_POST['personal-password']) ? $_POST['personal-password'] : null;
$oldPassword = isset($_POST['oldpassword']) ? $_POST['oldpassword'] : '';

$cracklibCheck = shell_exec("echo $password | /usr/local/sbin/cracklib-check 2>&1 | xargs echo -n");

OC_Log::write('ChangePassword','Changing password for: '.$username.":".$cracklibCheck, \OC_Log::WARN);

if(substr($cracklibCheck, -4)!=": OK"){
	\OC_JSON::error(array("data" => array("message" => $cracklibCheck)));
	exit();
}

/*if (!\OC_User::checkPassword($username, $oldPassword)) {
	$l = new \OC_L10n('settings');
	\OC_JSON::error(array("data" => array("message" => $l->t("Wrong password")) ));
	exit();
}*/

if (!empty($password) && \OC_User::setPassword($username, $password)) {
	if(\OCP\App::isEnabled('files_sharding')){
		if(\OCA\FilesSharding\Lib::isMaster() && !\OCA\FilesSharding\Lib::onServerForUser($username)){
			// Update on the home server (to allow local/independent login)
			$serverURL = \OCA\FilesSharding\Lib::getServerForUser($username, true);
			$pwOk = \OCA\FilesSharding\Lib::ws('set_pw_hash', array('user_id'=>$username), true, true, $serverURL);
			if($pwOk['status']!='success'){
				OC_Log::write('ChangePassword','ERROR: Could not change password for: '.
				$username." on ".$serverURL, \OC_Log::ERROR);
			}
		}
	}
	\OC_JSON::success();
} else {
	\OC_JSON::error();
}

