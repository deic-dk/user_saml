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

	OCP\App::checkAppEnabled('user_saml');

	$sspPath = empty($_COOKIE['saml_ssp_path'])?OCP\Config::getAppValue('user_saml', 'saml_ssp_path', ''):
		$_COOKIE['saml_ssp_path'];
	$sspAuthClass = empty($_COOKIE['saml_auth_class'])?OCP\Config::getAppValue('user_saml', 'saml_auth_class', 'SimpleSAML_Auth_Simple'):
		$_COOKIE['saml_auth_class'];
	$spSource = OCP\Config::getAppValue('user_saml', 'saml_sp_source', '');
	$autocreate = OCP\Config::getAppValue('user_saml', 'saml_autocreate', false);

	if (!empty($sspPath) && !empty($spSource)) {
		include_once $sspPath;
		$auth = new $sspAuthClass($spSource);
		$auth->requireAuth();
	}
