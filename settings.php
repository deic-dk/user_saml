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

require_once __DIR__ . '/../../lib/base.php';

OC_Util::checkAdminUser();

$params = array('saml_ssp_path', 'saml_auth_class', 'saml_sp_source', 'saml_force_saml_login', 'saml_autocreate',
		'saml_update_user_data', 'saml_protected_groups', 'saml_default_group', 'saml_username_mapping',
		'saml_email_mapping', 'saml_quota_mapping', 'saml_default_quota', 'saml_displayname_mapping',
		'saml_group_mapping', 'saml_affiliation_mapping', 'saml_group_admin');

OCP\Util::addscript('user_saml', 'settings');
OCP\Util::addstyle('user_saml', 'saml');

// fill template
$tmpl = new OCP\Template( 'user_saml', 'settings');
foreach ($params as $param) {
		$value = htmlentities(OCP\Config::getAppValue('user_saml', $param,''));
		$tmpl->assign($param, $value);
}

// settings with default values
$tmpl->assign( 'saml_ssp_path', OCP\Config::getAppValue('user_saml', 'saml_ssp_path', '/var/www/simplesamlphp/lib/_autoload.php'));
$tmpl->assign( 'saml_auth_class', OCP\Config::getAppValue('user_saml', 'saml_auth_class', 'SimpleSAML_Auth_Simple'));
$tmpl->assign( 'saml_sp_source', OCP\Config::getAppValue('user_saml', 'saml_sp_source', 'default-sp'));
$tmpl->assign( 'saml_force_saml_login', OCP\Config::getAppValue('user_saml', 'saml_force_saml_login', 0));
$tmpl->assign( 'saml_autocreate', OCP\Config::getAppValue('user_saml', 'saml_autocreate', 0));
$tmpl->assign( 'saml_update_user_data', OCP\Config::getAppValue('user_saml', 'saml_update_user_data', 0));
$tmpl->assign( 'saml_protected_groups', OCP\Config::getAppValue('user_saml', 'saml_protected_groups', ''));
$tmpl->assign( 'saml_default_group', OCP\Config::getAppValue('user_saml', 'saml_default_group', ''));
$tmpl->assign( 'saml_username_mapping', OCP\Config::getAppValue('user_saml', 'saml_username_mapping', 'uid'));
$tmpl->assign( 'saml_email_mapping', OCP\Config::getAppValue('user_saml', 'saml_email_mapping', 'mail'));
$tmpl->assign( 'saml_displayname_mapping', OCP\Config::getAppValue('user_saml', 'saml_displayname_mapping', 'displayName'));
$tmpl->assign( 'saml_quota_mapping', OCP\Config::getAppValue('user_saml', 'saml_quota_mapping', ''));
$tmpl->assign( 'saml_default_quota', OCP\Config::getAppValue('user_saml', 'saml_default_quota', ''));
$tmpl->assign( 'saml_group_mapping', OCP\Config::getAppValue('user_saml', 'saml_group_mapping', ''));
$tmpl->assign( 'saml_affiliation_mapping', OCP\Config::getAppValue('user_saml', 'saml_affiliation_mapping', ''));

return $tmpl->fetchPage();

