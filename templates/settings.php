<form id="saml" action="#" method="post">
	<div id="samlSettings" class="section">
    <h2><?php p($l->t('SAML Authentication backend'));?></h2>
	<ul>
		<li><a href="#samlSettings-1"><?php p($l->t('Basic'));?></a></li>
        <li><a href="#samlSettings-2"><?php p($l->t('Mapping'));?></a></li>
	</ul>
	<fieldset id="samlSettings-1">
		<p><label for="saml_ssp_path"><?php p($l->t('SimpleSAMLphp path'));?></label><input type="text" id="saml_ssp_path" name="saml_ssp_path" value="<?php p($_['saml_ssp_path']); ?>"></p>
		<p><label for="saml_auth_class"><?php p($l->t('SimpleSAMLphp class'));?></label><input type="text" id="saml_auth_class" name="saml_auth_class" value="<?php p($_['saml_auth_class']); ?>"></p>
		<p><label for="saml_sp_source"><?php p($l->t('SimpleSAMLphp SP source'));?></label><input type="text" id="saml_sp_source" name="saml_sp_source" value="<?php p($_['saml_sp_source']); ?>"></p>
		<p><label for="saml_force_saml_login"><?php p($l->t('Force SAML login?'));?></label><input type="checkbox" id="saml_force_saml_login" name="saml_force_saml_login" <?php p((($_['saml_force_saml_login'] != false) ? 'checked="checked"' : '')); ?>></p>
		<p><label for="saml_autocreate"><?php p($l->t('Autocreate user after saml login?'));?></label><input type="checkbox" id="saml_autocreate" name="saml_autocreate" <?php p((($_['saml_autocreate'] != false) ? 'checked="checked"' : '')); ?>></p>
		<p><label for="saml_update_user_data"><?php p($l->t('Update user data after login?'));?></label><input type="checkbox" id="saml_update_user_data" name="saml_update_user_data" <?php p((($_['saml_update_user_data'] != false) ? 'checked="checked"' : '')); ?>></p>
		<p><label for="saml_protected_groups"><?php p($l->t('Groups that will not be unlinked from the user when syncing with the IdP'));?></label><input type="text" id="saml_protected_groups" name="saml_protected_groups" value="<?php p($_['saml_protected_groups']); ?>" />
		<br><?php p($l->t('(protected group are multivalued, use comma to separate the values)')); ?></p> 
		<p><label for="saml_default_group"><?php p($l->t('Default group when autocreating users and not group data found for the user'));?></label><input type="text" id="saml_default_group" name="saml_default_group" value="<?php p($_['saml_default_group']); ?>"></p>
	</fieldset>
	<fieldset id="samlSettings-2">
		<p><label for="saml_username_mapping"><?php p($l->t('Username'));?></label><input type="text" id="saml_username_mapping" name="saml_username_mapping" value="<?php p($_['saml_username_mapping']); ?>" /></p>
		<p><label for="saml_email_mapping"><?php p($l->t('Email'));?></label><input type="text" id="saml_email_mapping" name="saml_email_mapping" value="<?php p($_['saml_email_mapping']); ?>" /></p>
		<p><label for="saml_displayname_mapping"><?php p($l->t('DisplayName'));?></label><input type="text" id="saml_displayname_mapping" name="saml_displayname_mapping" value="<?php p($_['saml_displayname_mapping']); ?>" /></p>
		<p><label for="saml_quota_mapping"><?php p($l->t('Quota'));?></label><input type="text" id="saml_quota_mapping" name="saml_quota_mapping" value="<?php p($_['saml_quota_mapping']); ?>" /></p>
		<p><label for="saml_default_quota"><?php p($l->t('Quota Default'));?></label><input type="text" id="saml_default_quota" name="saml_default_quota" value="<?php p($_['saml_default_quota']); ?>" title="<?php echo $l->t('in bytes');?>" /></p>
		<p><label for="saml_group_mapping"><?php p($l->t('Group'));?></label><input type="text" id="saml_group_mapping" name="saml_group_mapping" value="<?php p($_['saml_group_mapping']); ?>" /></p>
		<p><label for="saml_affiliation_mapping"><?php p($l->t('Affiliation'));?></label><input type="text" id="saml_affiliation_mapping" name="saml_affiliation_mapping" value="<?php p($_['saml_affiliation_mapping']); ?>" /></p>
	</fieldset>
	<input type="hidden" name="requesttoken" value="<?php echo $_['requesttoken'] ?>" id="requesttoken">
	<input type="button" id="save_saml_settings" value="Save" /><span id="samlMsg"></span>
	</div>

</form>
