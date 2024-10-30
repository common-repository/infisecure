<?php
/**
 * InfiSecure is a robust web security platform to detect and block online threats
 *
 * @category:InfiSecure
 * @package: InfiSecure
 * @copyright: InfiSecure 2017
 * See COPYING.txt for license details.
 * @license: InfiSecure 2017 license
 * @author: InfiSecure Dev Team
 * @keywords:
 */
class InfiSecure_Setting {
    protected $_settingId = 'infisecure_setting';
    protected $_settingDefaultValue = array(
        'is_active' => 0,
        'sub_code' => '',
        'auth_header' => '',
        'infisecure_domain' => '',
        'api_path' => '',
        'api_url_scheme'=> '',
        'cookies_domain' => '',
        'dns_domain_ttl' => '',
        'dns_domain_cache' => '',
        'lnis_ip_parameter' => 'REMOTE_ADDR',
        'lnis_session_parameter' => 'PHPSESSID',
        'lnis_static_resource_filter' => 'css|jpg|png|gif|js',
        'include_session' => 0
    );

    public function __construct()
    {
        add_action('init', array($this, 'init'));
        add_action('admin_init', array($this, 'admin_init'));
        add_action('admin_menu', array($this, 'addSettingPage'));
    }

    public function activate()
    {
        update_option($this->_settingId, $this->_settingDefaultValue);
    }

    public function deactivate()
    {
        delete_option($this->_settingId);
    }

    public function init()
    {
        get_option($this->_settingId);
    }

    public function admin_init()
    {
        register_setting('infisecure_option', $this->_settingId, array($this, 'validate'));
    }

    public function addSettingPage()
    {
        add_options_page(
            'InfiSecure Setting',
            'InfiSecure Setting',
            'manage_options',
            'infisecure_option',
            array($this, 'renderSettingPage')
        );
    }
    public function renderSettingPage() {
        $options = get_option($this->_settingId);
        ?>
        <div class="wrap">
            <h2>InfiSecure Setting</h2>
            <form method="post" action="options.php">
                <?php settings_fields('infisecure_option'); ?>
                <table class="form-table">
                    <tr valign="top"><th scope="row">Enable:</th>
                        <td>
                            <input type="checkbox" name="<?php echo $this->_settingId?>[is_active]" value="1"
                                <?php if ($options['is_active']) {?> checked="checked"<?php }?> />
                        </td>
                    </tr>
                    <tr valign="top"><th scope="row">Sub Code:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[sub_code]" value="<?php echo isset($options['sub_code'])?
                                $options['sub_code']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">Auth Header:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[auth_header]" value="<?php echo isset($options['auth_header'])?
                                $options['auth_header']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">Infisecure Domain:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[infisecure_domain]" value="<?php echo isset($options['infisecure_domain'])?
                                $options['infisecure_domain']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">API Path:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[api_path]" value="<?php echo isset($options['api_path'])?
                                $options['api_path']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">API URL Schema:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[api_url_scheme]" value="<?php echo isset($options['api_url_scheme'])?
                                $options['api_url_scheme']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">Cookies Domain:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[cookies_domain]" value="<?php echo isset($options['cookies_domain'])?
                                $options['cookies_domain']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">DNS Domain TTL:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[dns_domain_ttl]" value="<?php echo isset($options['dns_domain_ttl'])?
                                $options['dns_domain_ttl']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">DNS Domain Cache:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[dns_domain_cache]" value="<?php echo isset($options['dns_domain_cache'])?
                                $options['dns_domain_cache']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">IP Parameter:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[lnis_ip_parameter]" value="<?php echo isset($options['lnis_ip_parameter'])?
                                $options['lnis_ip_parameter']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">Session Parameter:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[lnis_session_parameter]" value="<?php echo isset($options['lnis_session_parameter'])?
                                $options['lnis_session_parameter']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">Static Resource Filter:</th>
                        <td><input type="text" style="width: 300px;" name="<?php echo $this->_settingId?>[lnis_static_resource_filter]" value="<?php echo isset($options['lnis_static_resource_filter'])?
                                $options['lnis_static_resource_filter']:''; ?>" /></td>
                    </tr>
                    <tr valign="top"><th scope="row">Include Session Data:</th>
                        <td>
                            <input type="checkbox" name="<?php echo $this->_settingId?>[include_session]" value="1"
                                <?php if ($options['include_session']) {?> checked="checked"<?php }?> />
                        </td>
                    </tr>
                </table>
                <p class="submit">
                    <input type="submit" class="button-primary" value="<?php _e('Save Changes') ?>" />
                </p>
            </form>
        </div>
        <?php
    }

    public function validate($input)
    {

        $valid = array();
        $valid['is_active'] = sanitize_text_field($input['is_active']);
        $valid['sub_code'] = sanitize_text_field($input['sub_code']);
        $valid['auth_header'] = sanitize_text_field($input['auth_header']);
        $valid['infisecure_domain'] = sanitize_text_field($input['infisecure_domain']);
        $valid['api_path'] = sanitize_text_field($input['api_path']);
        $valid['api_url_scheme'] = sanitize_text_field($input['api_url_scheme']);
        $valid['cookies_domain'] = sanitize_text_field($input['cookies_domain']);
        $valid['dns_domain_ttl'] = sanitize_text_field($input['dns_domain_ttl']);
        $valid['dns_domain_cache'] = sanitize_text_field($input['dns_domain_cache']);
        $valid['lnis_ip_parameter'] = sanitize_text_field($input['lnis_ip_parameter']);
        $valid['lnis_session_parameter'] = sanitize_text_field($input['lnis_session_parameter']);
        $valid['lnis_static_resource_filter'] = sanitize_text_field($input['lnis_static_resource_filter']);
        $valid['include_session'] = sanitize_text_field($input['include_session']);

        if (strlen($valid['sub_code']) == 0) {
            add_settings_error(
                'sub_code',
                'sub_code_texterror',
                'Please enter a valid Sub Code',
                'error'
            );
            $valid['sub_code'] = $this->_settingDefaultValue['sub_code'];
        }
        if (strlen($valid['auth_header']) == 0) {
            add_settings_error(
                'auth_header',
                'auth_header_texterror',
                'Please enter a valid Auth Header',
                'error'
            );

            $valid['auth_header'] = $this->_settingDefaultValue['auth_header'];
        }
        if (strlen($valid['infisecure_domain']) == 0) {
            add_settings_error(
                'infisecure_domain',
                'infisecure_domain_texterror',
                'Please enter a valid Infisecure Domain',
                'error'
            );

            $valid['api_path'] = $this->_settingDefaultValue['api_path'];
        }
        if (strlen($valid['api_path']) == 0) {
            add_settings_error(
                'api_path',
                'api_path_texterror',
                'Please enter a valid API Path',
                'error'
            );

            $valid['api_path'] = $this->_settingDefaultValue['api_path'];
        }
        if (strlen($valid['api_url_scheme']) == 0) {
            add_settings_error(
                'api_url_scheme',
                'api_url_scheme_texterror',
                'Please enter a valid API Scheme',
                'error'
            );

            $valid['api_url_scheme'] = $this->_settingDefaultValue['api_url_scheme'];
        }
        if (strlen($valid['cookies_domain']) == 0) {
            add_settings_error(
                'cookies_domain',
                'cookies_domain_texterror',
                'Please enter a valid Cookies Domain',
                'error'
            );

            $valid['cookies_domain'] = $this->_settingDefaultValue['cookies_domain'];
        }
        if (strlen($valid['dns_domain_ttl']) == 0) {
            add_settings_error(
                'dns_domain_ttl',
                'dns_domain_ttl_texterror',
                'Please enter a valid DNS Domain TTL',
                'error'
            );

            $valid['dns_domain_ttl'] = $this->_settingDefaultValue['dns_domain_ttl'];
        }

        if (strlen($valid['lnis_ip_parameter']) == 0) {
            add_settings_error(
                'lnis_ip_parameter',
                'lnis_ip_parameter_texterror',
                'Please enter a valid IP parameter',
                'error'
            );

            $valid['lnis_ip_parameter'] = $this->_settingDefaultValue['lnis_ip_parameter'];
        }
        if (strlen($valid['lnis_session_parameter']) == 0) {
            add_settings_error(
                'lnis_session_parameter',
                'lnis_session_parameter_texterror',
                'Please enter a valid Session Parameter',
                'error'
            );

            $valid['lnis_session_parameter'] = $this->_settingDefaultValue['lnis_session_parameter'];
        }
        if (strlen($valid['lnis_static_resource_filter']) == 0) {
            add_settings_error(
                'lnis_static_resource_filter',
                'lnis_static_resource_filter_texterror',
                'Please enter a valid Static Resource Filter',
                'error'
            );

            $valid['lnis_static_resource_filter'] = $this->_settingDefaultValue['lnis_static_resource_filter'];
        }
        return $valid;
    }
}
new InfiSecure_Setting();