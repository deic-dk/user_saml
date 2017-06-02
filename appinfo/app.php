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

if (OCP\App::isEnabled('user_saml')) {
	$ocVersion = implode('.',OCP\Util::getVersion());
	if (version_compare($ocVersion,'5.0','<')) {
		if ( ! function_exists('p')) {
			function p($string) {
				print(OC_Util::sanitizeHTML($string));
			}
		}
	}
	
	require_once 'user_saml/user_saml.php';

	OCP\App::registerAdmin('user_saml', 'settings');
	
	// Use user_group_admin groups for group management if available
	if(OCP\App::isEnabled('user_group_admin')){
		OC::$CLASSPATH['OC_User_Group_Admin_Backend'] ='apps/user_group_admin/lib/backend.php';
		OC::$CLASSPATH['OC_User_Group_Admin_Util']    ='apps/user_group_admin/lib/util.php';
		OC_Group::useBackend( new OC_User_Group_Admin_Backend() );
	}

	// register user backend for non-webdav access
	if(!isset($_SERVER['REQUEST_URI']) ||
			strpos($_SERVER['REQUEST_URI'], OC::$WEBROOT ."/files/")!==0 &&
			strpos($_SERVER['REQUEST_URI'], OC::$WEBROOT ."/remote.php/")!==0){
		OC_User::useBackend( 'SAML' );
	}
	else{
		//OC_User::clearBackends();
		//OC_User::useBackend();
		OC_User::useBackend( 'SAML' );
	}

	OC::$CLASSPATH['OC_USER_SAML_Hooks'] = 'user_saml/lib/hooks.php';
	OCP\Util::connectHook('OC_User', 'pre_login', 'OC_USER_SAML_Hooks', 'pre_login');
	OCP\Util::connectHook('OC_User', 'post_login', 'OC_USER_SAML_Hooks', 'post_login');
	OCP\Util::connectHook('OC_User', 'logout', 'OC_USER_SAML_Hooks', 'logout');

	$forceLogin = OCP\Config::getAppValue('user_saml', 'saml_force_saml_login', false) && shouldEnforceAuthentication();

	if( (isset($_GET['app']) && $_GET['app'] == 'user_saml') || (!OCP\User::isLoggedIn() && $forceLogin && !isset($_GET['admin_login']) )) {

		require_once 'user_saml/auth.php';

		if (!OC_User::login('', '')) {
			$error = true;
			OC_Log::write('saml','Error trying to authenticate the user', OC_Log::DEBUG);
		}
		
		if (isset($_GET["linktoapp"])) {
			$path = OC::$WEBROOT . '/?app='.$_GET["linktoapp"];
            if (isset($_GET["linktoargs"])) {
				$path .= '&'.urldecode($_GET["linktoargs"]);
			}
			header( 'Location: ' . $path);
			exit();
		}

		OC::$REQUESTEDAPP = '';
		OC_Util::redirectToDefaultPage();
	}

	// We load the login prompt only if we're stand-alone or on the sharding master
	//if(/*strlen($_SERVER['REQUEST_URI'])<=1 &&*/ !OCP\User::isLoggedIn() &&
		//(!OCP\App::isEnabled('files_sharding') || \OCA\FilesSharding\Lib::isMaster())){
		// Load js code in order to render the SAML link and to hide parts of the normal login form
		OCP\Util::addScript('user_saml', 'utils');
	//}
	
	if(OCP\App::isEnabled('files_sharding') && OCP\User::isLoggedIn() && strlen($_SERVER['REQUEST_URI'])>1 &&
	strpos($_SERVER['REQUEST_URI'], '/index.php/settings')===FALSE &&
	strpos($_SERVER['REQUEST_URI'], '/index.php/avatar/')===FALSE &&
	strpos($_SERVER['REQUEST_URI'], 'logout')===FALSE &&
	strpos($_SERVER['REQUEST_URI'], '/ajax/')===FALSE &&
	strpos($_SERVER['REQUEST_URI'], '/jqueryFileTree.php')===FALSE &&
	strpos($_SERVER['REQUEST_URI'], '/firstrunwizard/')===FALSE &&
	strpos($_SERVER['REQUEST_URI'], '/ws/')===FALSE &&
	strpos($_SERVER['REQUEST_URI'], '/sites/')===FALSE &&
	strpos($_SERVER['REQUEST_URI'], '/apps/files_picocms/')===FALSE &&
	substr($_SERVER['REQUEST_URI'], -3)!='.js' &&
	strpos($_SERVER['REQUEST_URI'], '/js/')===FALSE){
		$userid = \OCP\User::getUser();
		$redirect = OCA\FilesSharding\Lib::getServerForUser($userid);
		if(!empty($redirect)){
			$backup1 = OCA\FilesSharding\Lib::getServerForUser($userid, false,
					OCA\FilesSharding\Lib::$USER_SERVER_PRIORITY_BACKUP_1);
			$backup2 = OCA\FilesSharding\Lib::getServerForUser($userid, false,
					OCA\FilesSharding\Lib::$USER_SERVER_PRIORITY_BACKUP_2);
			$uri = preg_replace('|^'.OC::$WEBROOT.'|', '', $_SERVER['REQUEST_URI']);
			// The question mark is needed to not end up on slave login page
			if($uri=='/'){
				$uri = '/?';
			}
			$parsedRedirect = parse_url($redirect);
			$parsedBackup1 = empty($backup1)?'':parse_url($backup1);
			$parsedBackup2 = empty($backup2)?'':parse_url($backup2);
			if($_SERVER['HTTP_HOST']!==$parsedRedirect['host'] &&
					(empty($parsedBackup1)||$_SERVER['HTTP_HOST']!==$parsedBackup1['host']) &&
					(empty($parsedBackup2)||$_SERVER['HTTP_HOST']!==$parsedBackup2['host'])){
				$redirect_full = rtrim($redirect, '/').'/'.ltrim($uri, '/');
				$redirect_full = preg_replace("/(\?*)app=user_saml(\&*)/", "$1", $redirect_full);
				$redirect_full = preg_replace('|/+$|', '/', $redirect_full);
				OC_USER_SAML_Hooks::setRedirectCookie();
				OC_Log::write('user_saml', 'Redirecting to URL '.$redirect_full.'-->'.serialize($backup1), OC_Log::WARN);
				header("HTTP/1.1 307 Temporary Redirect");
				header('Location: ' . $redirect_full);
				exit();
			}
		}
	}
}

/*
* Checks if requiring SAML authentication on current URL makes sense when
* forceLogin is set.
*
* Disables it when using the command line too.
* 
* Most of this function contributed by David.Jericho@aarnet.edu.au
*/
function shouldEnforceAuthentication()
 {
	if(OC::$CLI){
		return false;
	}
	$script_filename = basename($_SERVER['SCRIPT_FILENAME']);
	$forceLogin = !in_array($script_filename,
		array(
			'cron.php',
			'public.php',
			'remote.php',
			'status.php',
		)
	);

	if(OCP\App::isEnabled('files_sharding') && isset($_COOKIE[\OCA\FilesSharding\Lib::$LOGIN_OK_COOKIE])){
		OC_Log::write('saml','Redirected from master, already logged in.', OC_Log::DEBUG);
		return false;
		}

	if($forceLogin){
		OC_Log::write('saml','Consider a forced login because SCRIPT FILENAME scripts not found; script_filename ' . basename($_SERVER['SCRIPT_FILENAME']), OC_Log::DEBUG);
	}

	/*
	* If there's no referer, the URI and referer tests below can never evaluate as true, so return now
	*/
	if(!isset($_SERVER['HTTP_REFERER'])){
		OC_Log::write('saml','No referer set, so returning a status for forced login status for ' . $_SERVER['REQUEST_URI'], OC_Log::DEBUG);
		return $forceLogin;
	};

	/*
	* This is the tricky bit in OC7 as it uses translations.php via index.php, but this is how the
	* forced login is done on the landing page too
	*/

	/* First case - translations.php run through index.php - permit without login */
	$request_uri = basename($_SERVER['REQUEST_URI']);
	if($request_uri === "translations.php" && $script_filename === "index.php"){
		OC_Log::write('saml','translations.php accessed through index.php, so don\'t force login', OC_Log::DEBUG);
		return false;
	}

	/* Second case - oc.js with the asset pipeline refered from public.php - permit without login
	* Set $referer as all further cases require it
	*/
	$referer = basename($_SERVER['HTTP_REFERER']);
	if(preg_match( "/^oc.js\?v=.*$/", $request_uri ) && preg_match ("/^public.php\?service=files.*$/", $referer)){
		OC_Log::write('saml','oc.js refered from public.php, so don\'t force login', OC_Log::DEBUG);
		return false;
	}

	/* Third case - list.php refered from public.php - permit without login */
	if(preg_match( "/^list.php\?t=[a-z0-9]*.*$/", $request_uri ) && preg_match ("/^public.php\?service=files.*$/", $referer)) {
		OC_Log::write('saml','list.php refered from public.php, so don\'t force login', OC_Log::DEBUG);
		return false;
	}

	/* Fourth case - share.php refered from public.php - permit without login */
	if ( preg_match( "/^share.php\?fetch=getItemsSharedStatuses*.*$/", $request_uri ) && preg_match ("/^public.php\?service=files.*$/", $referer) ) {
		OC_Log::write('saml','share.php refered from public.php, so don\'t force login', OC_Log::DEBUG);
		return false;
	}
		/* Fifth case, public folder upload - list.php refered from public.php - permit without login */
		if ( preg_match( "/^list.php\?t=[a-z0-9]*.*$/", $request_uri ) && preg_match ("/^public.php\?service=files.*$/", $referer) ) {
						OC_Log::write('saml','list.php refered from public.php, so don\'t force login', OC_Log::DEBUG);
						return false;
		}
		/* Sixth case, public folder upload - upload.php refered from public.php - permit without login */
		if ( preg_match( "/^upload.php$/", $request_uri ) && preg_match ("/^public.php\?service=files.*$/", $referer) ) {
						OC_Log::write('saml','upload.php refered from public.php, so don\'t force login', OC_Log::DEBUG);
						return false;
		}
	if ( $forceLogin ) {
		OC_Log::write('saml','forceLogin because forceLogin is still set; request_uri ' . $request_uri . ', referer ' . $referer . ', script_filename '. $script_filename, OC_Log::INFO);
	}

	return $forceLogin;
}

