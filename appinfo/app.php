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
			(strpos($_SERVER['REQUEST_URI'], OC::$WEBROOT ."/remote.php/")!==0 ||
			// This is to avoid that the connectivity checks of the admin page
			// flushes the session.
			!empty($_SERVER['HTTP_REFERER']) && substr($_SERVER['HTTP_REFERER'], -25)=="/index.php/settings/admin") &&
			strpos($_SERVER['REQUEST_URI'], OC::$WEBROOT ."/sharingin/")!==0 &&
			strpos($_SERVER['REQUEST_URI'], OC::$WEBROOT ."/sharingout/")!==0 &&
			strpos($_SERVER['REQUEST_URI'], OC::$WEBROOT ."/groupfolders/")!==0
			){
		OC_User::useBackend( 'SAML' );
	}
	// for webdav access we don't need saml
	else{
		//OC_User::clearBackends();
		//OC_User::useBackend();
		//OC_User::useBackend( 'SAML' );
		return;
	}

	OC::$CLASSPATH['OC_USER_SAML_Hooks'] = 'user_saml/lib/hooks.php';
	OCP\Util::connectHook('OC_User', 'pre_login', 'OC_USER_SAML_Hooks', 'pre_login');
	OCP\Util::connectHook('OC_User', 'post_login', 'OC_USER_SAML_Hooks', 'post_login');
	OCP\Util::connectHook('OC_User', 'logout', 'OC_USER_SAML_Hooks', 'logout');

	$myForceLogin = OCP\Config::getAppValue('user_saml', 'saml_force_saml_login', false) &&
		shouldEnforceAuthentication();
	
	// This is to address the issue of Firefox apparently sending an empty PHP_AUTH_USER header,
	// which triggers the functions in the stack trace below, eventually causing the session file
	// to be deleted.
	/*
	 OCA\\FilesSharding\\FileSessionHandler->destroy('698b64aa0e2768b...')\n#1 
	 \/usr\/local\/www\/owncloud\/lib\/private\/user.php(237): 
	 session_regenerate_id(true)\n#2 \/usr\/local\/www\/owncloud\/lib\/base.php(951): 
	 OC_User::login('test2', 'dummy')\n#3 \/usr\/local\/www\/owncloud\/lib\/base.php(850): 
	 OC::tryFormLogin()\n#4 \/usr\/local\/www\/owncloud\/lib\/base.php(787): 
	 OC::handleLogin()\n#5 \/usr\/local\/www\/owncloud\/index.php(36): 
	 OC::handleRequest()\n#6 {main}
	 */
	if(isset($_SERVER['PHP_AUTH_USER']) && empty($_SERVER['PHP_AUTH_USER'])){
		unset($_SERVER['PHP_AUTH_USER']);
	}
	
	if( (isset($_GET['app']) && $_GET['app'] == 'user_saml' ||
			!OCP\User::isLoggedIn() && $myForceLogin) && !isset($_GET['admin_login']) ) {

		require_once 'user_saml/auth.php';

		if (!OC_User::login('', '')) {
			$error = true;
			OC_Log::write('saml','Error trying to authenticate the user', OC_Log::ERROR);
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
	
	function testRedirectUri($uri, $localPath){
		return strpos($uri, $localPath)===false || strpos($uri, $localPath)>strlen(\OC::$WEBROOT)+2;
	}

	$uriFull = empty($_SERVER['REQUEST_URI'])?'':$_SERVER['REQUEST_URI'];
	$uri_parts = explode('?', $uriFull, 2);
	$uri = preg_replace('|^'.\OC::$WEBROOT.'|', '', $uri_parts[0]);
	$uri = '/'.ltrim($uri, '/');
	if(OCP\App::isEnabled('files_sharding') && OCP\User::isLoggedIn() && strlen($uri)>1 &&
			testRedirectUri($uri, '/index.php/settings') &&
			testRedirectUri($uri, '/index.php/avatar/') &&
			strpos($uriFull, '?logout=')===false && strpos($uriFull, '&logout=')===false &&
			testRedirectUri($uri, '/ajax/') &&
			testRedirectUri($uri, '/jqueryFileTree.php') &&
			testRedirectUri($uri, '/firstrunwizard/') &&
			testRedirectUri($uri, '/ws/') &&
	/*If a user is logged in, but tries to access a public share, let him and don't redirect him to his own server*/
			testRedirectUri($uri, '/shared/') &&
			testRedirectUri($uri, '/apps/files_sharing/public.php') &&
			testRedirectUri($uri, '/apps/files_pdfviewer/viewer.php') &&
			testRedirectUri($uri, '/sites/') &&
			testRedirectUri($uri, '/apps/files_picocms/') &&
			testRedirectUri($uri, '/sharingout/') &&
			testRedirectUri($uri, '/groups/') &&
			testRedirectUri($uri, '/apps/user_group_admin/appinfo/api.php') &&
			substr($uri, -4)!='.css' &&
			substr($uri, -3)!='.js' &&
			testRedirectUri($uri, '/js/') &&
			testRedirectUri($uri, '/apps/user_group_admin/external_collaborator_verify.php') &&
			testRedirectUri($uri, '/apps/user_saml/ajax/save_settings.php')){
		$userid = \OCP\User::getUser();
		if(strpos($uri, "/ocs/v1.php/apps/files_sharing/api/")===0){
			// Don't redirect js/ajax calls - not allowed by security. (Proxying done instead).
			if(isset($_SERVER['HTTP_REQUESTTOKEN']) || isset($_SERVER['REDIRECT_HTTP_REQUESTTOKEN']) ||
				\OCA\FilesSharding\Lib::isMaster()){
				return;
			}
			// Redirect iOS et al. That works...
			else{
				$redirect = OCA\FilesSharding\Lib::getMasterURL();
				// Pass on the file ID as item_source
				if(!empty($_POST) && !empty($_POST['path'])){
					$fileInfo = \OC\Files\Filesystem::getFileInfo($_POST['path']);
					//$fileID = \OCA\FilesSharding\Lib::getFileId($_POST['path']);
					if(!empty($fileInfo)){
						$fileID = $fileInfo['fileid'];
						$fileType = $fileInfo->getType()===\OCP\Files\FileInfo::TYPE_FOLDER?'folder':'file';
					}
				}
			}
		}
		else{
			$redirect = OCA\FilesSharding\Lib::getServerForUser($userid);
		}
		if(!empty($redirect)){
			$backup1 = OCA\FilesSharding\Lib::getServerForUser($userid, false,
					OCA\FilesSharding\Lib::$USER_SERVER_PRIORITY_BACKUP_1);
			$backup2 = OCA\FilesSharding\Lib::getServerForUser($userid, false,
					OCA\FilesSharding\Lib::$USER_SERVER_PRIORITY_BACKUP_2);
			// The question mark is needed to not end up on slave login page
			if($uriFull=='/'){
				$uriFull = '/?';
			}
			$parsedRedirect = parse_url($redirect);
			$parsedBackup1 = empty($backup1)?'':parse_url($backup1);
			$parsedBackup2 = empty($backup2)?'':parse_url($backup2);
			
			if($_SERVER['HTTP_HOST']!==$parsedRedirect['host'] &&
					(empty($parsedBackup1)||$_SERVER['HTTP_HOST']!==$parsedBackup1['host']) &&
					(empty($parsedBackup2)||$_SERVER['HTTP_HOST']!==$parsedBackup2['host']) &&
					!OCA\FilesSharding\Lib::isHostMe($redirect) &&
					!empty($_SERVER['REQUEST_URI']) && strlen($_SERVER['REQUEST_URI'])>18 &&
					substr($_SERVER['REQUEST_URI'], -19)!="change_password.php"){
						$redirect_full = rtrim($redirect, '/').'/'.ltrim($uriFull, '/');
				$redirect_full = preg_replace("/(\?*)app=user_saml(\&*)/", "$1", $redirect_full);
				$redirect_full = preg_replace('|/+$|', '/', $redirect_full);
				if(!empty($fileID)){
					$redirect_full = $redirect_full.'?item_source='.$fileID.'&item_type='.$fileType;
				}
				OC_USER_SAML_Hooks::setRedirectCookie();
				OC_Log::write('user_saml', 'Redirecting to URL '.$uriFull.'-->'.$redirect_full.'-->'.serialize($backup1), OC_Log::WARN);
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
			'settings.php'
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
	if(($request_uri === "translations.php" || strpos($_SERVER['REQUEST_URI'], OC::$WEBROOT."/avatar/")===0) &&
			$script_filename === "index.php"){
		OC_Log::write('saml','translations.php or /avatar/ accessed through index.php, so don\'t force login', OC_Log::DEBUG);
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

