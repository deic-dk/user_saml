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

/**
 * This class contains all hooks.
 */
class OC_USER_SAML_Hooks {

	private static $MASTER_LOGIN_OK_COOKIE = "oc_ok";
	private static $COOKIE_DOMAIN = '.data.deic.dk';

	public static function post_login($parameters) {
		$uid = '';
    $userid = $parameters['uid'];
    $samlBackend = new OC_USER_SAML();
    $ocUserDatabase = new OC_User_Database();
    
    // Redirect regardless of whether the user has authenticated with SAML or not.
    // Since this is a post_login hook, he will have authenticated in some way and have a valid session.
    if ($ocUserDatabase->userExists($userid)) {
			// Set user attributes for sharding
			$display_name = \OCP\Config::getUserValue(\OCP\User::getUser(), 'settings', 'email');
			$email = \OCP\Config::getUserValue(\OCP\User::getUser(), 'settings', 'email');
			$groups = \OC_Group::getUserGroups($userid);
			OC_Log::write('saml','Setting user attributes: '.$userid.":".$display_name.":".$email.":".join($groups),OC_Log::INFO);
			self::setAttributes($display_name, $email, $groups);
			
			// TODO: generalize check_user
			self::user_redirect($userid);
		}

    if (!$samlBackend->auth->isAuthenticated()) {
    	return false;
    }
    // else
    $attributes = $samlBackend->auth->getAttributes();
    
    //$email = "<pre>" . print_r($attributes, 1) . "</pre>";
    //$headers = 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
    //error_log($email, 1, 'cbri@dtu.dk', $headers);
    
    $usernameFound = false;
    foreach($samlBackend->usernameMapping as $usernameMapping) {
    	if (array_key_exists($usernameMapping, $attributes) && !empty($attributes[$usernameMapping][0])) {
    		$usernameFound = true;
    		$uid = $attributes[$usernameMapping][0];
    		OC_Log::write('saml','Authenticated user '.$uid,OC_Log::INFO);
    		break;
    	}
    }
    
    if (!$usernameFound || $uid !== $userid) {
    	return false;
    }
    // else
    $attrs = get_user_attributes($uid, $samlBackend);    
    
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
    		OC_Log::write('saml','Invalid username "'.$uid.'", allowed chars "a-zA-Z0-9" and "_.@-" ',OC_Log::DEBUG);
    		return false;
    	}
    	// Reject users we don't allow to autocreate an account
    	if(isset($uid) && trim($uid)!='' && !OC_User::userExists($uid) && !self::check_user_attributes($attributes) ) {
    		$failCookieName = 'saml_auth_fail';
    		$userCookieName = 'saml_auth_fail_user';
    		$expire = 0;//time()+60*60*24*30;
    		$expired = time()-3600;
    		$path = '/';
    		$domain = $COOKIE_DOMAIN;
    		setcookie($failCookieName, "notallowed:".$uid, $expire, $path, $domain, false, false);
    		setcookie($userCookieName, $uid, $expire, $path, $domain, false, false);
    		$spSource = 'default-sp';
    		$auth = new SimpleSAML_Auth_Simple($spSource);
    		OC_Log::write('saml','Rejected user "'.$uid, OC_Log::ERROR);
    		$auth->logout('https://data.deic.dk/');
    		return false;
    	}
    	// Create new user
    	$random_password = OC_Util::generateRandomBytes(20);
    	OC_Log::write('saml','Creating new user: '.$uid, OC_Log::INFO);
    	OC_User::createUser($uid, $random_password);
    	if(OC_User::userExists($uid)) {
    		self::update_user_data($uid, $attrs, true);
    		self::user_redirect($userid);
    	}
    }
    else{
    	if ($samlBackend->updateUserData) {
    		self::update_user_data($uid, $attrs, false);
    		self::user_redirect($userid);
    	}
    }
    //self::setAttributes($saml_display_name, $saml_email, $saml_groups);
    return true;
	}
	
	private static function get_user_attributes($uid, $samlBackend) {
		$attributes = $samlBackend->auth->getAttributes();
		$result = array();
	
		$result['email'] = '';
		foreach ($samlBackend->mailMapping as $mailMapping) {
			if (array_key_exists($mailMapping, $attributes) && !empty($attributes[$mailMapping][0])) {
				$result['email'] = $attributes[$mailMapping][0];
				break;
			}
		}
	
		$result['display_name'] = '';
		foreach ($samlBackend->displayNameMapping as $displayNameMapping) {
			if (array_key_exists($displayNameMapping, $attributes) && !empty($attributes[$displayNameMapping][0])) {
				$result['display_name'] = $attributes[$displayNameMapping][0];
				break;
			}
		}
	
		$result['groups'] = array();
		foreach ($samlBackend->groupMapping as $groupMapping) {
			if (array_key_exists($groupMapping, $attributes) && !empty($attributes[$groupMapping])) {
				$result['groups'] = array_merge($result['groups'], $attributes[$groupMapping]);
			}
		}
		if (empty($result['groups']) && !empty($samlBackend->defaultGroup)) {
			$result['groups'] = array($samlBackend->defaultGroup);
			OCP\Util::writeLog('saml','Using default group "'.$samlBackend->defaultGroup.'" for the user: '.$uid, OCP\Util::DEBUG);
		}
		$result['protected_groups'] = $samlBackend->protectedGroups;
	
		$result['quota'] = '';
		if (!empty($samlBackend->quotaMapping)) {
			foreach ($samlBackend->quotaMapping as $quotaMapping) {
				if (array_key_exists($quotaMapping, $attributes) && !empty($attributes[$quotaMapping][0])) {
					$result['quota'] = $attributes[$quotaMapping][0];
					break;
				}
			}
			OCP\Util::writeLog('saml','Current quota: "'.$result['quota'].'" for user: '.$uid, OCP\Util::DEBUG);
		}
		if (empty($result['quota']) && !empty($samlBackend->defaultQuota)) {
			$result['quota'] = $samlBackend->defaultQuota;
			OCP\Util::writeLog('saml','Using default quota ('.$result['quota'].') for user: '.$uid, OCP\Util::DEBUG);
		}
	
		return $result;	
	}
	
	private static function update_user_data($uid, $attributes=array(), $just_created=false){
		OC_Util::setupFS($uid);
		OC_Log::write('saml','Updating data of the user: '.$uid." : ".OC_User::userExists($uid)." :: ".implode("::", $samlBackend->protectedGroups),OC_Log::INFO);
		if(isset($saml_email)) {
			update_mail($uid, $saml_email);
		}
		if (isset($saml_groups)) {
			update_groups($uid, $saml_groups, $samlBackend->protectedGroups, false);
		}
		// Check if a custom displayname has been set before updating the displayname with information from SAML
		// This is clumsy, but, for some reason, getDisplayName() doesn't work here. - CB
		if (isset($saml_display_name)) {
			$query = OC_DB::prepare('SELECT `displayname` FROM `*PREFIX*users` WHERE `uid` = ?');
			$result = $query->execute(array($uid))->fetchAll();
			$displayName = trim($result[0]['displayname'], ' ');
			if (empty($displayName)) {
				update_display_name($uid, $saml_display_name);
			}
		}
		if (isset($saml_quota)) {
			update_quota($uid, $saml_quota);
		}
	}

  private static function check_user_attributes($attributes){
    $entitlement = array_key_exists('eduPersonEntitlement' , $attributes) ? $attributes['eduPersonEntitlement'][0] : '';
    $schacHomeOrganization = array_key_exists('schacHomeOrganization' , $attributes) ? $attributes['schacHomeOrganization'][0]: '';
    $mail = array_key_exists('mail' , $attributes) ? $attributes['mail'][0]: '';
    return self::check_user($entitlement, $schacHomeOrganization, $mail);
  }
  
	private static function check_user($entitlement, $schacHomeOrganization, $mail){
    error_log('Checking user: '.$mail.':'.$schacHomeOrganization.':'.$entitlement);
    
    return substr($mail, -7)==="@sdu.dk" or substr($mail, -7)===".sdu.dk" or substr($mail, -7)==="@dtu.dk" or substr($mail, -7)===".dtu.dk" or $mail == "fror@dtu.dk" or $mail == "uhsk@dtu.dk" or $mail == "no-jusa@aqua.dtu.dk" or $mail == "cbri@dtu.dk" or $mail == "marbec@dtu.dk" or $mail == "tacou@dtu.dk" or $mail == "migka@dtu.dk" or $mail == "no-dtma@dtu.dk" or $mail == "christian@cabo.dk" or $mail == "frederik@orellana.dk" or $mail == "no-elzi@kb.dk" or $mail == "no-svc@kb.dk";
  }
  
  private static function user_redirect($userid){
		$redirect = self::get_user_redirect($userid);
		if(self::check_user("", "", $userid) && !empty($redirect)){
			header('Location: ' . $redirect);
			exit();
		}
	}
  
  private public function get_user_redirect($userid){
		if($userid == "frederik@orellana.dk"){
			// TODO: generalize this - i.e. introduce placing algoritme - and move somewhere upstream - to catch username/password logins
			return "https://silo1.data.deic.dk/";
		}
		return null;
	}


 public static function logout($parameters) {
		//self::unsetAttributes();
    $samlBackend = new OC_USER_SAML();
    if ($samlBackend->auth->isAuthenticated()) {
      OC_Log::write('saml', 'Executing SAML logout', OC_Log::INFO);
      $samlBackend->auth->logout();
    }
    return true;
  }
  
  // For files_sharding: put user data in session; set a short-lived cookie so slave can see user came from master.
   private static function setAttributes($saml_display_name, $saml_email, $saml_groups) {
		/*$secure_cookie = \OC_Config::getValue("forcessl", false);
		$expires = time() + \OC_Config::getValue('remember_login_cookie_lifetime', 60 * 60 * 24 * 15);
		setcookie("oc_display_name", $saml_display_name, $expires, \OC::$WEBROOT, '', $secure_cookie);
		setcookie("oc_mail", $saml_email, $expires, \OC::$WEBROOT, '', $secure_cookie);
		setcookie("oc_groups", json_encode($saml_groups), $expires, \OC::$WEBROOT, '', $secure_cookie);*/
		
		$short_expires = time() + \OC_Config::getValue('remember_login_cookie_lifetime', 5);
		setcookie(self::$MASTER_LOGIN_OK_COOKIE, "ok", $short_expires, \OC::$WEBROOT, self::$COOKIE_DOMAIN, true);
	
		$_SESSION["oc_display_name"] = $saml_display_name;
		$_SESSION["oc_mail"] = $saml_email;
		$_SESSION["oc_groups"] = $saml_groups;
	}

	
	private static function unsetAttributes() {
		$expires = time()-3600;
		
		/*setcookie("oc_display_name", '', $expires, \OC::$WEBROOT);
		setcookie("oc_mail", '', $expires, \OC::$WEBROOT);
		setcookie("oc_groups", '', $expires, \OC::$WEBROOT);*/
		
		setcookie(self::$MASTER_LOGIN_OK_COOKIE, "", $expires, \OC::$WEBROOT, self::$COOKIE_DOMAIN);
		unset($_SESSION["oc_display_name"]);
		unset($_SESSION["oc_mail"]);
		unset($_SESSION["oc_groups"]);
	}

	private static function update_mail($uid, $email) {
	  if ($email != OC_Preferences::getValue($uid, 'settings', 'email', '')) {
	    OC_Preferences::setValue($uid, 'settings', 'email', $email);
	    OC_Log::write('saml','Set email "'.$email.'" for the user: '.$uid, OC_Log::DEBUG);
	  }
	}
	
	
	private static function update_groups($uid, $groups, $protectedGroups=array(), $just_created=false) {
	
	  if(!$just_created) {
	    $old_groups = OC_Group::getUserGroups($uid);
	    foreach($old_groups as $group) {
	      if(!in_array($group, $protectedGroups) && !in_array($group, $groups)) {
	        OC_Group::removeFromGroup($uid,$group);
	        OC_Log::write('saml','Removed "'.$uid.'" from the group "'.$group.'"', OC_Log::DEBUG);
	      }
	    }
	  }
	
	  foreach($groups as $group) {
	    if (preg_match( '/[^a-zA-Z0-9 _\.@\-\/]/', $group)) {
	      OC_Log::write('saml','Invalid group "'.$group.'", allowed chars "a-zA-Z0-9" and "_.@-/" ',OC_Log::DEBUG);
	    }
	    else {
	      if (!OC_Group::inGroup($uid, $group)) {
	        if (!OC_Group::groupExists($group)) {
	          OC_Group::createGroup($group);
	          OC_Log::write('saml','New group created: '.$group, OC_Log::DEBUG);
	        }
	        OC_Group::addToGroup($uid, $group);
	        OC_Log::write('saml','Added "'.$uid.'" to the group "'.$group.'"', OC_Log::DEBUG);
	      }
	    }
	  }
	}
	
	private static function update_display_name($uid, $displayName) {
	  // I inject directly into the database here rather than using the method setDisplayName(), 
	  // which doesn't work. -CB 
	  $query = OC_DB::prepare('UPDATE `*PREFIX*users` SET `displayname` = ? WHERE LOWER(`uid`) = ?');                            
	  $query->execute(array($displayName, $uid));
	  //OC_User::setDisplayName($uid, $displayName);
	}
	
	function update_quota($uid, $quota) {
		if (!empty($quota)) {
			\OCP\Config::setUserValue($uid, 'files', 'quota', \OCP\Util::computerFileSize($quota));
		}
	}

}
