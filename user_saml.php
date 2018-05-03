<?php

/**
 * ownCloud - user_saml
 *
 * @author Sixto Martin <smartin@yaco.es>
 * @copyright 2012 Yaco Sistemas // CONFIA
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

class OC_USER_SAML extends OC_User_Backend {

	// cached settings
	protected $sspPath;
	protected $spSource;
	public $forceLogin;
	public $autocreate;
	public $updateUserData;
	public $protectedGroups;
	public $defaultGroup;
	public $usernameMapping;
	public $mailMapping;
	public $displayNameMapping;
	public $quotaMapping;
	public $defaultQuota;
	public $groupMapping;
	public $auth;
	public $defaultFreeQuota;
	public $affiliationMapping;
	
	
	public function __construct() {
		$this->sspPath = OCP\Config::getAppValue('user_saml', 'saml_ssp_path', '');
		$this->spSource = OCP\Config::getAppValue('user_saml', 'saml_sp_source', '');
		$this->forceLogin = OCP\Config::getAppValue('user_saml', 'saml_force_saml_login', false);
		$this->autocreate = OCP\Config::getAppValue('user_saml', 'saml_autocreate', false);
		$this->updateUserData = OCP\Config::getAppValue('user_saml', 'saml_update_user_data', false);
		$this->defaultGroup = OCP\Config::getAppValue('user_saml', 'saml_default_group', '');
		$trim_patterns = Array('/,\s+/', '/\s+,/', '/^\s+/', '/\s+$/');
		$trim_replacements = Array(',', ',', '', '', '');
		$this->protectedGroups = explode (',', preg_replace($trim_patterns, $trim_replacements, OCP\Config::getAppValue('user_saml', 'saml_protected_groups', '')));
		$this->usernameMapping = explode (',', preg_replace($trim_patterns, $trim_replacements, OCP\Config::getAppValue('user_saml', 'saml_username_mapping', '')));
		$this->mailMapping = explode (',', preg_replace($trim_patterns, $trim_replacements, OCP\Config::getAppValue('user_saml', 'saml_email_mapping', '')));
		$this->displayNameMapping = explode (',', preg_replace($trim_patterns, $trim_replacements, OCP\Config::getAppValue('user_saml', 'saml_displayname_mapping', '')));
		$this->quotaMapping = explode (',', preg_replace('/\s+/', '', OCP\Config::getAppValue('user_saml', 'saml_quota_mapping', '')));
		$this->defaultQuota = OCP\Config::getAppValue('user_saml', 'saml_default_quota', '');
		$this->defaultFreeQuota = OCP\Config::getAppValue('user_saml', 'saml_default_freequota', ''); 
		$this->groupMapping = explode (',', preg_replace($trim_patterns, $trim_replacements, OCP\Config::getAppValue('user_saml', 'saml_group_mapping', '')));
		$this->affiliationMapping = explode (',', preg_replace($trim_patterns, $trim_replacements, OCP\Config::getAppValue('user_saml', 'saml_affiliation_mapping', '')));
		if (!empty($this->sspPath) && !empty($this->spSource)) {
			include_once $this->sspPath."/lib/_autoload.php";

			$this->auth = new SimpleSAML_Auth_Simple($this->spSource);

			if (isset($_COOKIE["user_saml_logged_in"]) AND $_COOKIE["user_saml_logged_in"] AND !$this->auth->isAuthenticated()) {
				unset($_COOKIE["user_saml_logged_in"]);
				setcookie("user_saml_logged_in", null, -1);
				OCP\User::logout();
			}
		}
	}


	public function checkPassword($uid, $password) {

		if(!$this->auth->isAuthenticated()) {
			return false;
		}

		$attributes = $this->auth->getAttributes();
		
		// Translate number code friendly name. TODO: get rid of this hard-coded path
		include "/usr/local/www/simplesamlphp/attributemap/name2oid.php";
		
		foreach($this->usernameMapping as $usernameMapping) {
			if (array_key_exists($usernameMapping, $attributes) && !empty($attributes[$usernameMapping][0])) {
				$uid = $attributes[$usernameMapping][0];
				OC_Log::write('saml','Authenticated user '.$uid,OC_Log::DEBUG);
				return $uid;
			}
			if(array_key_exists($usernameMapping, $attributemap)){
				$friendlyAttribute = $attributemap[$usernameMapping];
				if (array_key_exists($friendlyAttribute, $attributes) && !empty($attributes[$friendlyAttribute][0])) {
					$uid = $attributes[$friendlyAttribute][0];
					OC_Log::write('saml','Authenticated user '.$uid,OC_Log::DEBUG);
					return $uid;
				}
			}
		}
		
		OC_Log::write('saml','Not found attribute used to get the username at the requested saml attribute assertion',OC_Log::DEBUG);
		$secure_cookie = OC_Config::getValue("forcessl", false);
		$expires = time() + OC_Config::getValue('remember_login_cookie_lifetime', 60*60*24*15);
		setcookie("user_saml_logged_in", "1", $expires, '', '', $secure_cookie);

		return false;

	}
	
	
	// From lib/private/user/database.php
	// Apparently OC cannot use methods from more than one backend.
	
	private $cache = array();

	public function setDisplayName($uid, $displayName) {
		if ($this->userExists($uid)) {
			$query = OC_DB::prepare('UPDATE `*PREFIX*users` SET `displayname` = ? WHERE LOWER(`uid`) = LOWER(?)');
			$query->execute(array($displayName, $uid));
			$this->cache[$uid]['displayname'] = $displayName;

			return true;
		}

		return false;
	}
	
	public function getDisplayName($uid) {
		$this->loadUser($uid);
		return empty($this->cache[$uid]['displayname']) ? $uid : $this->cache[$uid]['displayname'];
	}
	
	public function userExists($uid) {
		
		if(empty($uid)){
			return false;
		}
	
		// This is only for ajax/ws calls when sharing
		if(\OCP\App::isEnabled('files_sharding') && !OCA\FilesSharding\Lib::isMaster() && empty(OC_User::getUser())){
			$userExists = \OCA\FilesSharding\Lib::ws('userExists', array('user_id' => $uid));
			return $userExists;
		}
		
		$this->loadUser($uid);
		return !empty($this->cache[$uid]);
	}
	
	private function loadUser($uid) {
		if (empty($this->cache[$uid])) {
			$query = OC_DB::prepare('SELECT `uid`, `displayname` FROM `*PREFIX*users` WHERE LOWER(`uid`) = LOWER(?)');
			$result = $query->execute(array($uid));

			if (OC_DB::isError($result)) {
				OC_Log::write('core', OC_DB::getErrorMessage($result), OC_Log::ERROR);
				return false;
			}

			while ($row = $result->fetchRow()) {
				$this->cache[$uid]['uid'] = $row['uid'];
				$this->cache[$uid]['displayname'] = $row['displayname'];
			}
		}

		return true;
	}
	
	
	
}

