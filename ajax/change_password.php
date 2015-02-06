<?php




OCP\JSON::checkAppEnabled('importer');
OC_JSON::checkLoggedIn();



$username = OC_User::getUser();
$password = isset($_POST['personal-password']) ? $_POST['personal-password'] : null;
$oldPassword = isset($_POST['oldpassword']) ? $_POST['oldpassword'] : '';

OC_Log::write('ChangePassword','Changing password for: '.$username, \OC_Log::INFO);

/*if (!\OC_User::checkPassword($username, $oldPassword)) {
	$l = new \OC_L10n('settings');
	\OC_JSON::error(array("data" => array("message" => $l->t("Wrong password")) ));
	exit();
}*/

if (!is_null($password) && \OC_User::setPassword($username, $password)) {
	\OC_JSON::success();
} else {
	\OC_JSON::error();
}

