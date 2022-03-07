<?php
/**
 * ownCloud - user_saml
 *
 * @author Sixto Martin <smartin@yaco.es>
 * @copyright 2012 Yaco Sistemas // CONFIA
 * @author Frederik Orellana <fror@dtu.dk>
 * @author Mads Freek Petersen <fror@dtu.dk>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**
 * This class contains all hooks.
 */
class OC_USER_SAML_Hooks {

	public static function pre_login($parameters) {
		// This just serves to avoid multiple warnings issued when
		// OC_User::isLoggedIn() calls OC_User::login($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])
		// and $_SERVER['PHP_AUTH_PW'] is empty, but $_SERVER['PHP_AUTH_USER'] is not.
		// This scenario is used by the login mechanisms of chooser, and pre_login should be defined
		// in that app. But for some reason, this one is called first...
		// And we still get one login failed warning.
		//OCP\Util::writeLog('saml','PRE: '.serialize($parameters), OCP\Util::WARN);
		if(!empty($_SERVER['PHP_AUTH_USER']) && empty($_SERVER['PHP_AUTH_PW'])){
			unset($_SERVER['PHP_AUTH_PW']);
		}
	}

	public static function post_login($parameters) {

		$userid = $parameters['uid'];

		if(\OCP\App::isEnabled('files_sharding') ){
			// Check if someone is trying to log in as admin from a non-white-listed IP.
			\OCA\FilesSharding\Lib::checkAdminIP($userid);
			// Do nothing if we're sharding and not on the master
			if(!\OCA\FilesSharding\Lib::isMaster()){
				return true;
			}
		}

		$samlBackend = new \OC_USER_SAML();
		$ocUserDatabase = new \OC_User_Database();
		// Redirect regardless of whether the user has authenticated with SAML or not.
		// Since this is a post_login hook, he will have authenticated in some way and have a valid session.
		if ($ocUserDatabase->userExists($userid)) {
			// Set user attributes for sharding
			$display_name = \OCP\User::getDisplayName($userid);
			$email = \OCP\Config::getUserValue($userid, 'settings', 'email');
			$groups = \OC_Group::getUserGroups($userid);
			$quota = \OC_Preferences::getValue($userid,'files','quota');
			$freequota = \OC_Preferences::getValue($userid, 'files_accounting','freequota');
			$affiliation = \OCP\Config::getUserValue($userid, 'user_group_admin', 'affiliation');

			\OC_Util::teardownFS($userid);
			\OC_Util::setupFS($userid);

			\OC_Log::write('saml','Setting user attributes: '.$userid.":".$display_name.":".$email.":".
				join($groups).":".$quota, \OC_Log::WARN);
			self::setAttributes($userid, $display_name, $email, $groups, $quota, $freequota, $affiliation);

			\OC_Log::write('saml','Updating user '.$userid.":".\OCP\USER::getUser().": ".
				$samlBackend->updateUserData, \OC_Log::WARN);

			if($samlBackend->updateUserData){
				$attrs = self::get_user_attributes($userid, $samlBackend);
				self::update_user_data($userid, $samlBackend, $attrs, false);
			}

			self::user_redirect($userid);
		}

		if (!$samlBackend->auth->isAuthenticated()) {
			return false;
		}

		$attributes = $samlBackend->auth->getAttributes();

		$uid = '';
		$usernameFound = false;
		foreach($samlBackend->usernameMapping as $usernameMapping) {
			if (array_key_exists($usernameMapping, $attributes) && !empty($attributes[$usernameMapping][0])) {
				$usernameFound = true;
				$uid = $attributes[$usernameMapping][0];
				\OC_Log::write('saml', 'Authenticated user '.$uid, \OC_Log::INFO);
				break;
			}
			$attributeCode = \OC_USER_SAML::getAtributeCode($usernameMapping);
			if (!empty($attributeCode) && array_key_exists($attributeCode, $attributes) && !empty($attributes[$attributeCode][0])) {
				$usernameFound = true;
				$uid = $attributes[$attributeCode][0];
				\OC_Log::write('saml', 'Authenticated user '.$uid, \OC_Log::INFO);
				break;
			}
		}
		
		if(!$usernameFound || $uid !== $userid){
			return false;
		}

		$attrs = self::get_user_attributes($uid, $samlBackend);

		if(!$ocUserDatabase->userExists($uid)){
			// If autocreate is not enabled - back off
			if(!$samlBackend->autocreate){
				return false;
			}
			// Apparently it is necessary to clear the uid first, to be able to create the user in the DB
			$userManager = \OC_User::getManager();
			$userManager->delete($uid);
			// Reject invalid user names
			if (preg_match( '/[^a-zA-Z0-9 _\.@\-]/', $uid)) {
				\OC_Log::write('saml', 'Invalid username "'.$uid.'", allowed chars "a-zA-Z0-9" and "_.@-" ', \OC_Log::DEBUG);
				return false;
			}
			$cookiedomain = \OCP\App::isEnabled('files_sharding')?\OCA\FilesSharding\Lib::getCookieDomain():null;
			// Reject users we don't allow to autocreate an account
			if(isset($uid) && trim($uid)!='' && !\OC_User::userExists($uid) && !self::check_user_attributes($attributes) ) {
				$failCookieName = 'saml_auth_fail';
				$userCookieName = 'saml_auth_fail_user';
				$expire = 0;//time()+60*5;
				$path = '/';
				setcookie($failCookieName, "notallowed:".$uid, $expire, $path, $cookiedomain, false, false);
				setcookie($userCookieName, $uid, $expire, $path, $cookiedomain, false, false);
				// To prevent blocking from modern browsers, see
				// https://stackoverflow.com/questions/58191969/how-to-fix-set-samesite-cookie-to-none-warning-chrome-extension
				/*$date = new DateTime();
				$date->setTimestamp($expires);
				header('Set-Cookie: '.$failCookieName.'=notallowed:'.$uid.'; expires='.$date->format(DateTime::COOKIE).
						'; path='.$path.'; domain='.$cookiedomain.'; sameSite=None; secure');
				header('Set-Cookie: '.$userCookieName.'='.$uid.'; expires='.$date->format(DateTime::COOKIE).
						'; path='.$path.'; domain='.$cookiedomain.'; sameSite=None; secure');*/
				\OC_Log::write('saml', 'Rejected user '.$uid, \OC_Log::ERROR);
				if(\OCP\App::isEnabled('files_sharding') && !\OCA\FilesSharding\Lib::isMaster()){
					//$samlBackend->auth->logout(!\OCA\FilesSharding\Lib::getMasterURL());
				}
				else{
					//$samlBackend->auth->logout();
				}
				return false;
			}
			// Create new user
			$random_password = \OC_Util::generateRandomBytes(20);
			\OC_Log::write('saml', 'Creating new user: '.$uid, \OC_Log::WARN);
			\OC_User::createUser($uid, $random_password);
			if(\OC_User::userExists($uid)){
				$userDir = '/'.$uid.'/files';
				\OC\Files\Filesystem::init($uid, $userDir);
				if($samlBackend->updateUserData){
					self::update_user_data($uid, $samlBackend, $attrs, true);
					if(\OCP\App::isEnabled('files_sharding') && \OCA\FilesSharding\Lib::isMaster()){
						// This returns the master
						//$site = \OCA\FilesSharding\Lib::dbGetSite(null);
						$site = self::choose_site_for_user($attributes);
						$server_id = \OCA\FilesSharding\Lib::dbChooseServerForUser($uid, $attrs['email'], $site,
								\OCA\FilesSharding\Lib::$USER_SERVER_PRIORITY_PRIMARY, null);
						\OC_Log::write('saml', 'Setting server for new user: '.$server_id, \OC_Log::WARN);
						\OCA\FilesSharding\Lib::dbSetServerForUser($uid, $server_id,
						\OCA\FilesSharding\Lib::$USER_SERVER_PRIORITY_PRIMARY,
						\OCA\FilesSharding\Lib::$USER_ACCESS_ALL);
					}
				}
				self::setAttributes($uid, $attrs['display_name'], $attrs['email'], $attrs['groups'], $attrs['quota'],
						$attrs['freequota'], $attrs['affiliation']);
			}
		}
		else{
			\OC_Log::write('saml', 'Updating user '.$uid.":".$samlBackend->updateUserData, \OC_Log::INFO);
			// Check if a user with the email address as uid has been migrated from old service
			require_once __DIR__ . '/../../firstrunwizard/lib/firstrunwizard.php';
			if(\OCP\App::isEnabled('firstrunwizard') && \OCA_FirstRunWizard\Config::isenabled() &&
					!empty($attrs['email']) && $uid!=$attrs['email'] && \OC_User::userExists($attrs['email'])){
						\OCA\FilesSharding\Lib::migrateUser($attrs['email'], $uid);
			}
			if($samlBackend->updateUserData){
				self::update_user_data($uid, $samlBackend, $attrs, false);
			}
		}
		self::user_redirect($userid);
		return true;
	}

	private static function get_user_attributes($uid, $samlBackend) {
		$attributes = $samlBackend->auth->getAttributes();
		\OC_Log::write('saml', 'SAML attributes: '.serialize($attributes), \OC_Log::WARN);
		$result = array();
	
		$result['email'] = '';
		foreach ($samlBackend->mailMapping as $mailMapping) {
			if (array_key_exists($mailMapping, $attributes) && !empty($attributes[$mailMapping][0])) {
				$result['email'] = $attributes[$mailMapping][0];
				break;
			}
			$attributeCode = \OC_USER_SAML::getAtributeCode($mailMapping);
			if (!empty($attributeCode) && array_key_exists($attributeCode, $attributes) && !empty($attributes[$attributeCode][0])) {
				$result['email'] = $attributes[$attributeCode][0];
				break;
			}
		}
	
		$result['display_name'] = '';
		foreach ($samlBackend->displayNameMapping as $displayNameMapping) {
			$dn_attributes = explode(" ", $displayNameMapping);
			foreach($dn_attributes as $dn_mapping){
				$attributeCode = \OC_USER_SAML::getAtributeCode($dn_mapping);
				if (array_key_exists($dn_mapping, $attributes) && !empty($attributes[$dn_mapping][0])) {
					$result['display_name'] .= " ".$attributes[$dn_mapping][0];
				}
				elseif (!empty($attributeCode) && array_key_exists($attributeCode, $attributes) && !empty($attributes[$attributeCode][0])) {
					$result['display_name'] .= " ".$attributes[$attributeCode][0];
				}
			}
		}
		$result['display_name'] = trim($result['display_name']);
	
		$result['groups'] = array();
		foreach ($samlBackend->groupMapping as $groupMapping) {
			if (array_key_exists($groupMapping, $attributes) && !empty($attributes[$groupMapping])) {
				$result['groups'] = array_merge($result['groups'], $attributes[$groupMapping]);
			}
			$attributeCode = \OC_USER_SAML::getAtributeCode($groupMapping);
			if (!empty($attributeCode) && array_key_exists($attributeCode, $attributes) && !empty($attributes[$attributeCode][0])) {
				$result['groups'] = array_merge($result['groups'], $attributes[$attributeCode]);
			}
		}
		if (empty($result['groups']) && strpos($uid, '@')>0) {
			$atIndex = strpos($uid, '@');
			$domain = substr($uid, $atIndex+1);
			\OCP\Util::writeLog('saml','Using UID domain as group "'.$domain.'" for the user: '.$uid, \OCP\Util::DEBUG);
			$result['groups'] = array($domain);
		}
		if (empty($result['groups']) && !empty($samlBackend->defaultGroup)) {
			$result['groups'] = array($samlBackend->defaultGroup);
			\OCP\Util::writeLog('saml','Using default group "'.$samlBackend->defaultGroup.'" for the user: '.$uid, \OCP\Util::DEBUG);
		}
		$result['protected_groups'] = $samlBackend->protectedGroups;

		$result['quota'] = '';
		if (!empty($samlBackend->quotaMapping)) {
			foreach ($samlBackend->quotaMapping as $quotaMapping) {
				if (array_key_exists($quotaMapping, $attributes) && !empty($attributes[$quotaMapping][0])) {
					$result['quota'] = $attributes[$quotaMapping][0];
					break;
				}
				$attributeCode = \OC_USER_SAML::getAtributeCode($quotaMapping);
				if (!empty($attributeCode) && array_key_exists($attributeCode, $attributes) && !empty($attributes[$attributeCode][0])) {
					$result['quota'] = $attributes[$attributeCode][0];
					break;
				}
			}
			\OCP\Util::writeLog('saml','SAML quota: "'.$result['quota'].'" for user: '.$uid, \OCP\Util::WARN);
		}
		if (empty($result['quota']) && !empty($samlBackend->defaultQuota)) {
			$result['quota'] = $samlBackend->defaultQuota;
			\OCP\Util::writeLog('saml','Using default quota ('.$result['quota'].') for user: '.$uid, \OCP\Util::WARN);
		}

		$result['freequota'] = '';
		if (!empty($samlBackend->defaultFreeQuota)) {
		  $result['freequota'] = $samlBackend->defaultFreeQuota;
		  \OCP\Util::writeLog('saml','Using default free quota ('.$result['freequota'].') for user: '.$uid, \OCP\Util::WARN);
		}

		$result['affiliation'] = '';
		if (!empty($samlBackend->affiliationMapping)) {
			foreach ($samlBackend->affiliationMapping as $affiliationMapping) {
				if (array_key_exists($affiliationMapping, $attributes) && !empty($attributes[$affiliationMapping][0])) {
					$result['affiliation'] = $attributes[$affiliationMapping][0];
					break;
				}
				$attributeCode = \OC_USER_SAML::getAtributeCode($affiliationMapping);
				if (!empty($attributeCode) && array_key_exists($attributeCode, $attributes) && !empty($attributes[$attributeCode][0])) {
					$result['affiliation'] = $attributes[$attributeCode][0];
					break;
				}
			}
			\OCP\Util::writeLog('saml','SAML affiliation: "'.$result['affiliation'].'" for user: '.$uid, \OCP\Util::WARN);
		}

		return $result;
	}

	private static function update_user_data($uid, $samlBackend, $attributes=array(), $just_created=false){
		//\OC_Util::setupFS($uid);
		\OC_Log::write('saml', 'Updating data of the user: '.$uid." : ".\OC_User::userExists($uid)." :: ".
			implode("::", $samlBackend->protectedGroups), \OC_Log::INFO);
		if(!empty($attributes['email'])) {
			self::update_mail($uid, $attributes['email']);
		}
		if(!empty($attributes['groups'])) {
			self::update_groups($uid, $attributes['groups'], $samlBackend->protectedGroups, false);
		}
		if($just_created && !empty($attributes['affiliation'])) {
			self::update_affiliation($uid, $attributes['affiliation']);
		}
		// Check if a custom displayname has been set before updating the displayname with information from SAML
		// This is clumsy, but, for some reason, getDisplayName() doesn't work here. - CB
		// Well, this sort of prevents changing your display name... - FO
		if (!empty($attributes['display_name'])) {
			/*$query = \OC_DB::prepare('SELECT `displayname` FROM `*PREFIX*users` WHERE `uid` = ?');
			$result = $query->execute(array($uid))->fetchAll();
			$displayName = trim($result[0]['displayname'], ' ');*/
			//if (empty($displayName)) {
				self::update_display_name($uid, $attributes['display_name']);
			//}
		}
		if(!empty($attributes['freequota'])){
			self::update_freequota($uid, $attributes['freequota']);
		}
		// Bump up quota if smaller than freequota
		if(!empty($attributes['freequota']) && !empty($attributes['quota']) &&
				(int)$attributes['freequota']>(int)$attributes['quota']){
			\OCP\Util::writeLog('saml','Updating quota from "'.$attributes['quota'].'" for user: '.$uid, \OCP\Util::WARN);
			$attributes['quota'] = $attributes['freequota'];
		}
		if(!empty($attributes['quota']) || $attributes['quota']==='0'){
			\OCP\Util::writeLog('saml','Updating quota to: "'.$attributes['quota'].'" for user: '.$uid, \OCP\Util::WARN);
			self::update_quota($uid, $attributes['quota']);
		}
	}

	private static function get_attribute($attribute, $attributes){
		$ret = array_key_exists($attribute, $attributes)?$attributes[$attribute][0]:'';
		if(empty($ret)){
			$attributeCode = \OC_USER_SAML::getAtributeCode($attribute);
			$ret = array_key_exists($attributeCode, $attributes)?$attributes[$attributeCode][0]:'';
			\OC_Log::write('saml', 'Code: '.$attribute.'-->'.$attributeCode.'-->'.$ret, \OC_Log::WARN);
		}
		return $ret;
	}

  // TODO: generalize this
	private static function check_user_attributes($attributes){
		\OC_Log::write('saml', 'Checking attributes: '.serialize($attributes), \OC_Log::WARN);
		$entitlement = self::get_attribute('eduPersonEntitlement', $attributes);
		$schacHomeOrganization = self::get_attribute('schacHomeOrganization', $attributes);
		$mail = self::get_attribute('mail', $attributes);
		return self::check_user($entitlement, $schacHomeOrganization, $mail);
	}

  // TODO: generalize this
	private static function check_user($entitlement, $schacHomeOrganization, $mail){
		\OC_Log::write('saml', 'Checking user: '.$mail.':'.$schacHomeOrganization.':'.$entitlement, \OC_Log::WARN);
		return true or substr($mail, -7)==="@sdu.dk" or substr($mail, -7)===".sdu.dk" or
		substr($mail, -7)==="@cbs.dk" or substr($mail, -7)===".cbs.dk" or
		substr($mail, -7)==="@dtu.dk" or substr($mail, -7)===".dtu.dk" or substr($mail, -8)==="@cern.ch" or
		$mail == "fror@dtu.dk" or $mail == "marbec@dtu.dk" or $mail == "tacou@dtu.dk" or
		$mail == "dtma@dtu.dk" or
		$mail == "christian@orellana.dk" or $mail == "frederik@orellana.dk";
	}

	// TODO: generalize this
	private static function choose_site_for_user($attributes){
		$entitlement = array_key_exists('eduPersonEntitlement' , $attributes) ? $attributes['eduPersonEntitlement'][0] : '';
		$schacHomeOrganization = array_key_exists('schacHomeOrganization' , $attributes) ? $attributes['schacHomeOrganization'][0]: '';
		$organizationName = array_key_exists('organizationName' , $attributes) ? $attributes['organizationName'][0]: '';
		$mail = array_key_exists('mail' , $attributes) ? $attributes['mail'][0]: '';
		return 	\OCA\FilesSharding\Lib::dbChooseSiteForUser($mail, $schacHomeOrganization, $organizationName, $entitlement);
	}

	private static function user_redirect($userid){

		if(!\OCP\App::isEnabled('files_sharding')){
			return;
		}

		$uri = preg_replace('|^'.\OC::$WEBROOT.'|', '', $_SERVER['REQUEST_URI']);

		if(strpos($uri, "/ocs/v1.php/apps/files_sharing/api/")===0){
			// Don't redirect js/ajax calls. That will produce an OPTIONS request to master...
			if(isset($_SERVER['HTTP_REQUESTTOKEN']) || isset($_SERVER['REDIRECT_HTTP_REQUESTTOKEN']) ||
					\OCA\FilesSharding\Lib::isMaster()){
				return;
			}
			else{
				$masterUrl = OCA\FilesSharding\Lib::getMasterURL();
				$redirect_full = rtrim($masterUrl, '/').'/'.ltrim($uri, '/');
				$redirect_full = preg_replace('|/+$|', '/', $redirect_full);
				// Pass on the file ID as item_source
				if(!empty($_POST) && !empty($_POST['path'])){
					$fileID = \OCA\FilesSharding\Lib::getFileId($_POST['path']);
					if(!empty($fileID)){
						$redirect_full = $redirect_full.'?item_source='.$fileID;
					}
				}
				\OC_Log::write('saml', 'Redirecting sharing queries back to master. '.serialize($_SERVER), \OC_Log::WARN);
				header("HTTP/1.1 307 Temporary Redirect");
				header('Location: ' . $redirect_full);
				exit();
			}
		}

		$redirect = \OCA\FilesSharding\Lib::getServerForUser($userid, false);
		$redirectInternal = OCA\FilesSharding\Lib::getServerForUser($userid, true);

		if(self::check_user("", "", $userid) && !empty($redirect)){
			// The question mark is needed to not end up on slave login page
			if($uri=='/'){
				$uri = '/?';
			}
			$parsedRedirect = parse_url($redirect);
			$parsedRedirectInternal = parse_url($redirectInternal);
			if($_SERVER['HTTP_HOST']!==$parsedRedirect['host'] &&
					$_SERVER['HTTP_HOST']!==$parsedRedirectInternal['host'] &&
					strpos($uri, '/sharingout/')===FALSE){
				$redirect_full = rtrim($redirect, '/').'/'.ltrim(\OC::$WEBROOT.$uri, '/');
				$redirect_full = preg_replace("/(\?*)app=user_saml(\&*)/", "$1", $redirect_full);
				$redirect_full = preg_replace('|/+$|', '/', $redirect_full);
				\OC_Log::write('saml', 'Redirecting to: '.$redirect_full, \OC_Log::WARN);
				header("HTTP/1.1 307 Temporary Redirect");
				header('Location: ' . $redirect_full);
				exit();
			}
		}
	}

	public static function logout($parameters) {

		if(\OCP\App::isEnabled('files_sharding') && !\OCA\FilesSharding\Lib::isMaster()){
			//return;
		}
		$cookiedomain = \OCP\App::isEnabled('files_sharding')?\OCA\FilesSharding\Lib::getCookieDomain():null;

		self::unsetAttributes();
		$samlBackend = new \OC_USER_SAML();
		if($samlBackend->auth->isAuthenticated()){
			\OC_Log::write('saml', 'Executing SAML logout', \OC_Log::WARN);
			//unset($_COOKIE['SimpleSAMLAuthToken']);
			//setcookie('SimpleSAMLAuthToken', '', time()-3600, \OC::$WEBROOT);
			$session = \OC::$server->getUserSession();
			$session->unsetMagicInCookie();
			$session->setUser(null);
			$session->setLoginName(null);
		}
		session_destroy();
		$session_id = session_id();
		\OC_Log::write('saml', 'Clearing session cookie '.$session_id, \OC_Log::WARN);
		unset($_COOKIE[$session_id]);
		setcookie($session_id, '', time()-3600, \OC::$WEBROOT, $cookiedomain);
		setcookie($session_id, '', time()-3600, \OC::$WEBROOT . '/', $cookiedomain);
		setcookie(\OCA\FilesSharding\Lib::$MASTER_LOGIN_COOKIE, '', time()-3600, \OC::$WEBROOT, $cookiedomain);
		setcookie(\OCA\FilesSharding\Lib::$MASTER_LOGIN_COOKIE, '', time()-3600, \OC::$WEBROOT . '/', $cookiedomain);
		// Not working for DTU
		//if($samlBackend->auth->isAuthenticated()){
		//	$samlBackend->auth->logout();
		//}
		return true;
	}

	public static function setRedirectCookie(){
		$short_expires = time() + \OC_Config::getValue('remember_login_cookie_lifetime', 30);
		$cookiedomain = \OCP\App::isEnabled('files_sharding')?\OCA\FilesSharding\Lib::getCookieDomain():null;
		setcookie(\OCA\FilesSharding\Lib::$LOGIN_OK_COOKIE, "ok", $short_expires,
			empty(\OC::$WEBROOT)?"/":\OC::$WEBROOT,
			$cookiedomain, true, true);
		setcookie(\OCA\FilesSharding\Lib::$MASTER_LOGIN_COOKIE, "ok", 0,
				empty(\OC::$WEBROOT)?"/":\OC::$WEBROOT,
				$cookiedomain, true, true);/*$date = new DateTime();
		$date->setTimezone(new DateTimeZone('GMT'));
		$date->setTimestamp($short_expires);
		header('Set-Cookie: '.\OCA\FilesSharding\Lib::$LOGIN_OK_COOKIE.'=ok; expires='.$date->format(DateTime::COOKIE).
				'; path='.(empty(\OC::$WEBROOT)?"/":\OC::$WEBROOT).'; domain='.$cookiedomain.'; sameSite=None; secure');*/
	}


	// For files_sharding: put user data in session; set a short-lived cookie so slave can see user came from master.
	private static function setAttributes($user_id, $saml_display_name, $saml_email, $saml_groups,
			$saml_quota, $saml_freequota, $saml_affiliation) {
		/*$secure_cookie = \OC_Config::getValue("forcessl", false);
		$expires = time() + \OC_Config::getValue('remember_login_cookie_lifetime', 60 * 60 * 24 * 15);
		setcookie("oc_display_name", $saml_display_name, $expires, \OC::$WEBROOT, '', $secure_cookie);
		setcookie("oc_mail", $saml_email, $expires, \OC::$WEBROOT, '', $secure_cookie);
		setcookie("oc_quota", $saml_quota, $expires, \OC::$WEBROOT, '', $secure_cookie);
		setcookie("oc_freequota", $saml_freequota, $expires, \OC::$WEBROOT, '', $secure_cookie);
		setcookie("oc_groups", json_encode($saml_groups), $expires, \OC::$WEBROOT, '', $secure_cookie);*/
		if(\OCP\App::isEnabled('files_sharding')){
			self::setRedirectCookie();
		}

		$_SESSION["oc_display_name"] = $saml_display_name;
		$_SESSION["oc_mail"] = $saml_email;
		$_SESSION["oc_groups"] = $saml_groups;
		$_SESSION["oc_quota"] = $saml_quota;
		$_SESSION["oc_freequota"] = $saml_freequota;
		$_SESSION["oc_affiliation"] = $saml_affiliation;
		if(\OCP\App::isEnabled('files_sharding') && \OCA\FilesSharding\Lib::isMaster()){
			//\OC_Util::setupFS();
			// Let slaves know which folders are data folders
			$dataFolders = \OCA\FilesSharding\Lib::dbGetDataFoldersList($user_id);
			$_SESSION["oc_data_folders"] = $dataFolders;
			// Have slaves use the same numeric ID for "storages".
			$view = \OC\Files\Filesystem::getView();
			$rootInfo = $view->getFileInfo('');
			$storageId = $rootInfo->getStorage()->getId();
			$numericStorageId = \OC\Files\Cache\Storage::getNumericStorageId($storageId);
			$_SESSION["oc_storage_id"] = $storageId;
			$_SESSION["oc_numeric_storage_id"] = $numericStorageId;
		}
	}


	private static function unsetAttributes() {
		$expires = time()-3600;
		$cookiedomain = \OCP\App::isEnabled('files_sharding')?\OCA\FilesSharding\Lib::getCookieDomain():null;

		/*setcookie("oc_display_name", '', $expires, \OC::$WEBROOT);
		setcookie("oc_mail", '', $expires, \OC::$WEBROOT);
		setcookie("oc_quota", '', $expires, \OC::$WEBROOT);
		setcookie("oc_groups", '', $expires, \OC::$WEBROOT);*/
		setcookie("oc_freequota", '', $expires, \OC::$WEBROOT, $cookiedomain);
		if(\OCP\App::isEnabled('files_sharding')){
			setcookie(\OCA\FilesSharding\Lib::$LOGIN_OK_COOKIE, "", $expires,
				empty(\OC::$WEBROOT)?"/":\OC::$WEBROOT, $cookiedomain);
			setcookie(\OCA\FilesSharding\Lib::$ACCESS_OK_COOKIE, "", $expires,
			empty(\OC::$WEBROOT)?"/":\OC::$WEBROOT, $cookiedomain);
			/*$date = new DateTime();
			$date->setTimestamp($expires);
			header('Set-Cookie: '.\OCA\FilesSharding\Lib::$LOGIN_OK_COOKIE.'=; expires='.$date->format(DateTime::COOKIE).
					'; path='.(empty(\OC::$WEBROOT)?"/":\OC::$WEBROOT).'; domain='.$cookiedomain.'; sameSite=None; secure');
			header('Set-Cookie: '.\OCA\FilesSharding\Lib::$ACCESS_OK_COOKIE.'=; expires='.$date->format(DateTime::COOKIE).
					'; path='.(empty(\OC::$WEBROOT)?"/":\OC::$WEBROOT).'; domain='.$cookiedomain.'; sameSite=None; secure');*/
		}
		if(!empty($_SESSION)){
			unset($_SESSION["oc_display_name"]);
			unset($_SESSION["oc_mail"]);
			unset($_SESSION["oc_groups"]);
			unset($_SESSION["oc_quota"]);
			unset($_SESSION["oc_freequota"]);
			unset($_SESSION["oc_data_folders"]);
			unset($_SESSION["oc_storage_id"]);
			unset($_SESSION["oc_numeric_storage_id"]);
			unset($_SESSION["oc_affiliation"]);
		}
	}

	private static function update_mail($uid, $email) {
		if ($email != \OC_Preferences::getValue($uid, 'settings', 'email', '')) {
			\OC_Preferences::setValue($uid, 'settings', 'email', $email);
			\OC_Log::write('saml','Set email "'.$email.'" for the user: '.$uid, \OC_Log::DEBUG);
		}
	}

	private static function update_affiliation($uid, $affiliation) {
		if ($affiliation != \OCP\Config::getUserValue($uid, 'user_group_admin', 'affiliation', '')) {
			\OCP\Config::setUserValue($uid, 'user_group_admin', 'affiliation', $affiliation);
			\OC_Log::write('saml','Set affiliation "'.$affiliation.'" for the user: '.$uid, \OC_Log::WARN);
		}
	}

	private static function update_groups($uid, $groups, $protectedGroups=array(), $just_created=false) {
		if(!$just_created && !empty($groups) && !\OCP\App::isEnabled('user_group_admin')) {
			\OC_Log::write('saml','Restricting group membership of '.$uid.' to the groups '.serialize($groups), \OC_Log::WARN);
			$old_groups = \OC_Group::getUserGroups($uid);
			foreach($old_groups as $group) {
				if(!in_array($group, $protectedGroups) && !in_array($group, $groups)) {
				// This does not affect groups from user_group_admin
					\OC_Group::removeFromGroup($uid,$group);
					\OC_Log::write('saml','Removed "'.$uid.'" from the group "'.$group.'"', \OC_Log::WARN);
				}
			}
		}
		foreach($groups as $group) {
			if (preg_match( '/[^a-zA-Z0-9 _\.@\-\/]/', $group)) {
				\OC_Log::write('saml','Invalid group "'.$group.'", allowed chars "a-zA-Z0-9" and "_.@-/" ', \OC_Log::DEBUG);
			}
			else {
				if(!\OC_Group::inGroup($uid, $group)) {
					if(!\OC_Group::groupExists($group)) {
						if(\OCP\App::isEnabled('user_group_admin')){
							\OC_User_Group_Admin_Util::createHiddenGroup($group);
						}
						else{
							\OC_Group::createGroup($group);
						}
						\OC_Log::write('saml','New group created: '.$group, \OC_Log::WARN);
					}
					if(\OCP\App::isEnabled('user_group_admin')){
						\OC_User_Group_Admin_Util::addToGroup($uid, $group, '', '');
					}
					else{
						\OC_Group::addToGroup($uid, $group);
					}
					\OC_Log::write('saml','Added "'.$uid.'" to the group "'.$group.'"', \OC_Log::WARN);
				}
			}
		}
	}

	private static function update_display_name($uid, $displayName) {
		// I inject directly into the database here rather than using the method setDisplayName(),
		// which doesn't work. -CB
		// because we're using the user_saml backend, and not the default one - see app.php. - FO
		//$query = \OC_DB::prepare('UPDATE `*PREFIX*users` SET `displayname` = ? WHERE LOWER(`uid`) = ?');
		//$query->execute(array($displayName, $uid));
		\OC_User::setDisplayName($uid, $displayName);
	}

	private static function update_quota($uid, $quota) {
		if (!empty($quota) || $attributes['quota']==='0') {
			\OCP\Config::setUserValue($uid, 'files', 'quota', $quota);
		}
	}

	private static function update_freequota($uid, $freequota) {
		if (!empty($freequota)) {
			\OCP\Config::setUserValue($uid, 'files_accounting', 'freequota', $freequota);
		}
	}
}

