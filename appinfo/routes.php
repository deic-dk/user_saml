<?php
/*Call this by overriding personal.js in your theme and replacing settings_personal_changepassword with my_settings_personal_changepassword in this file.*/
$this->create('my_settings_personal_changepassword', '/changepassword')
	->post()
	->action('OCA\UserSAML\ChangePassword\Controller', 'changePersonalPassword');
