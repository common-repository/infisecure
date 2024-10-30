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
class Infisecure_Config
{
    protected $_settingId = 'infisecure_setting';

    /*
     *  Enter your Subscriber Code (Subscriber code will be provided by the InfiSecure team)
     */
    public $lnis_sub_code = '';
    /*
     *  Enter your Auth Key (Auth Key will be provided by the InfiSecure team)
     */
    public $lnis_api_key= '';

    /*
     * Set the api and js urls will be provided by infisecure team
     */
    public $lnis_infisecure_domain = '';
    public $lnis_infisecure_api_path = '';
    public $lnis_url_scheme = '';
    public $lnis_cookie_domain = '';
    public $lnis_dns_domain_ttl = '';
    public $lnis_dns_domain_cache = '';
    public $lnis_cookie_path = '';
    /*
     * REMOTE_ADDR is the default, change this value if your servers are behind a firewall or proxy
     */
    public $lnis_ip_parameter = "";
    /*
     * PHPSESSID is the default session ID for PHP, please change accordingly
     */
    public $lnis_session_parameter = "";

    public $lnis_static_resource_filter = "";

    /*
     *  Milliseconds = 0, Seconds = 1
     *  Set the timeout option, depending on the version of the curl lib.
     *  If the curl version is greater than or equal to 7.16.2 the timeout_type
     *    should be 0 and if the curl
     *  version is less than 7.16.2, then the timeout_type should be 1.
     *
     *  Eg: If the Curl version is less then 7.16.2 then
     *        public $_timeout_type = 1;
     *        public $_timeout_value = 1;
     *    If the Curl version is greater than or equal to 7.16.2 then
     *        public $_timeout_type = 0;
     *        public $_timeout_value = 100;
     */
    public $lnis_timeout_type = 0;
    public $async_http_post = 0;
    public $lnis_timeout_value = 1000;

    public function __construct()
    {
        try {
            $settings = get_option($this->_settingId);
            if (isset($settings['is_active']) && $settings['is_active']) {
                $this->lnis_sub_code = isset($settings['sub_code'])?$settings['sub_code']:'';
                $this->lnis_api_key = isset($settings['auth_header'])?$settings['auth_header']:'';

                $this->lnis_infisecure_domain = isset($settings['infisecure_domain'])?$settings['infisecure_domain']:'';
                $this->lnis_infisecure_api_path = isset($settings['api_path'])?$settings['api_path']:'';
                $this->lnis_url_scheme = isset($settings['api_url_scheme'])?$settings['api_url_scheme']:'';
                $this->lnis_cookie_domain = isset($settings['cookies_domain'])?$settings['cookies_domain']:'';
                $this->lnis_dns_domain_ttl = isset($settings['dns_domain_ttl'])?$settings['dns_domain_ttl']:'';
                $this->lnis_dns_domain_cache = isset($settings['dns_domain_cache'])?$settings['dns_domain_cache']:'';
                $this->lnis_cookie_path = '/';
                $this->async_http_post = 0;
                $this->lnis_ip_parameter = isset($settings['lnis_ip_parameter'])?$settings['lnis_ip_parameter']:'';
                $this->lnis_session_parameter = isset($settings['lnis_session_parameter'])?
                    $settings['lnis_session_parameter']:'';
                $this->lnis_static_resource_filter = isset($settings['lnis_static_resource_filter'])?
                    $settings['lnis_static_resource_filter']:'';
                if (isset($settings['include_session']) && $settings['include_session']) {
                    if (isset($_SESSION) && (session_status() != PHP_SESSION_ACTIVE)) {
                        Session_Start();
                    }
                }
            }

        } catch (Exception $e) {

        }
        return false;
    }
}

