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

	static public function post_login($parameters) {
		$userid = $parameters['uid'];
		$samlBackend = new OC_USER_SAML();
		$ocUserDatabase = new OC_User_Database();

		if ($samlBackend->auth->isAuthenticated()) {
			$attributes = $samlBackend->auth->getAttributes();

			$usernameFound = false;
			foreach($samlBackend->usernameMapping as $usernameMapping) {
				if (array_key_exists($usernameMapping, $attributes) && !empty($attributes[$usernameMapping][0])) {
					$usernameFound = true;
					$uid = $attributes[$usernameMapping][0];
					OC_Log::write('saml','Authenticated user '.$uid,OC_Log::INFO);
					break;
				}
			}

			if ($usernameFound && $uid == $userid) {

				$attributes = $samlBackend->auth->getAttributes();

				$saml_email = '';
				foreach ($samlBackend->mailMapping as $mailMapping) {
					if (array_key_exists($mailMapping, $attributes) && !empty($attributes[$mailMapping][0])) {
						$saml_email = $attributes[$mailMapping][0];
						break;
					}
				}

				$saml_display_name = '';
				foreach ($samlBackend->displayNameMapping as $displayNameMapping) {
					if (array_key_exists($displayNameMapping, $attributes) && !empty($attributes[$displayNameMapping][0])) {
						$saml_display_name = $attributes[$displayNameMapping][0];
						break;
					}
				}

				$saml_groups = array();
				foreach ($samlBackend->groupMapping as $groupMapping) {
					if (array_key_exists($groupMapping, $attributes) && !empty($attributes[$groupMapping])) {
						$saml_groups = array_merge($saml_groups, $attributes[$groupMapping]);
					}
				}
				if (empty($saml_groups) && !empty($samlBackend->defaultGroup)) {
					$saml_groups = array($samlBackend->defaultGroup);
					OC_Log::write('saml','Using default group "'.$samlBackend->defaultGroup.'" for the user: '.$uid, OC_Log::DEBUG);
				}

				if (!$ocUserDatabase->userExists($uid)) {
					$userManager = \OC_User::getManager();
					$userManager->delete($uid);
					if (preg_match( '/[^a-zA-Z0-9 _\.@\-]/', $uid)) {
						OC_Log::write('saml','Invalid username "'.$uid.'", allowed chars "a-zA-Z0-9" and "_.@-" ',OC_Log::DEBUG);
						return false;
					}
					else {

						if(isset($uid) && trim($uid)!='' && !OC_User::userExists($uid) && !self::check_user_attributes($attributes) ) {
							$failCookieName = 'saml_auth_fail';
							$userCookieName = 'saml_auth_fail_user';
							$expire = 0;//time()+60*60*24*30;
							$expired = time()-3600;
							$path = '/';
							$domain = 'data.deic.dk';//this causes a dot to be prepended
							setcookie($failCookieName, "notallowed:".$uid, $expire, $path, $domain, false, false);
							setcookie($userCookieName, $uid, $expire, $path, $domain, false, false);
							$spSource = 'default-sp';
							$auth = new SimpleSAML_Auth_Simple($spSource);
							OC_Log::write('saml','Rejected user "'.$uid, OC_Log::ERROR);
							$auth->logout('https://data.deic.dk/');
							return false;
						}

						$random_password = OC_Util::generateRandomBytes(20);
						OC_Log::write('saml','Creating new user: '.$uid, OC_Log::INFO);
						OC_User::createUser($uid, $random_password);
						if(OC_User::userExists($uid)) {
							OC_Util::setupFS($uid);
							if (isset($saml_email)) {
								update_mail($uid, $saml_email);
							}
							if (isset($saml_groups)) {
								update_groups($uid, $saml_groups, $samlBackend->protectedGroups, true);
							}
							if (isset($saml_display_name)) {
								update_display_name($uid, $saml_display_name);
							}
						}
					}
				}
				else {
					if ($samlBackend->updateUserData) {
						OC_Util::setupFS($uid);
						OC_Log::write('saml','Updating data of the user: '.$uid." : ".OC_User::userExists($uid)." :: ".implode("::", $samlBackend->protectedGroups),OC_Log::INFO);
						if(isset($saml_email)) {
							update_mail($uid, $saml_email);
						}
						if (isset($saml_groups)) {
							update_groups($uid, $saml_groups, $samlBackend->protectedGroups, false);
						}
						if (isset($saml_display_name)) {
							update_display_name($uid, $saml_display_name);
						}
					}
				}
				return true;
			}
		}
		return false;
	}

	static public function check_user_attributes($attributes){
		$entitlement = array_key_exists('eduPersonEntitlement' , $attributes) ? $attributes['eduPersonEntitlement'][0] : '';
		$schacHomeOrganization = array_key_exists('schacHomeOrganization' , $attributes) ? $attributes['schacHomeOrganization'][0]: '';
		$mail = array_key_exists('mail' , $attributes) ? $attributes['mail'][0]: '';
		error_log('Checking user: '.$mail.':'.$schacHomeOrganization.':'.$entitlement);
		return substr($mail, -7)==="@dtu.dk" or $mail == "fror@dtu.dk" or $mail == "uhsk@dtu.dk" or $mail == "no-jusa@aqua.dtu.dk" or $mail == "cbri@dtu.dk" or $mail == "marbec@dtu.dk" or $mail == "tacou@dtu.dk" or $mail == "migka@dtu.dk" or $mail == "no-dtma@dtu.dk" or $mail == "christian@cabo.dk" or $mail == "no-frederik@orellana.dk" or $mail == "no-elzi@kb.dk" or $mail == "no-svc@kb.dk";
	}

	
	static public function logout($parameters) {
		$samlBackend = new OC_USER_SAML();
		if ($samlBackend->auth->isAuthenticated()) {
			OC_Log::write('saml', 'Executing SAML logout', OC_Log::WARN);
			$samlBackend->auth->logout();
		}
		return true;
	}

}


function update_mail($uid, $email) {
	if ($email != OC_Preferences::getValue($uid, 'settings', 'email', '')) {
		OC_Preferences::setValue($uid, 'settings', 'email', $email);
		OC_Log::write('saml','Set email "'.$email.'" for the user: '.$uid, OC_Log::DEBUG);
	}
}


function update_groups($uid, $groups, $protectedGroups=array(), $just_created=false) {

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
		if (preg_match( '/[^a-zA-Z0-9 _\.@\-]/', $group)) {
			OC_Log::write('saml','Invalid group "'.$group.'", allowed chars "a-zA-Z0-9" and "_.@-" ',OC_Log::DEBUG);
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

function update_display_name($uid, $displayName) {
	OC_User::setDisplayName($uid, $displayName);
}
