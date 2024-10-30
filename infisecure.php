<?php
/**
 * @package InfiSecure
 */
/*
Plugin Name: InfiSecure Plugin
Description:Protect your website from online frauds with infisecure. Detect and block bad bots,prevent web scraping & content theft and protect user data from hackers
Version: 1.0
Author: InfiSecure Dev Team
*/
class InfiSecure{

    // Constructor
    public function __construct() {
        register_activation_hook( __FILE__, array( $this, 'plugin_activation' ) );
        register_deactivation_hook( __FILE__, array( $this, 'plugin_deactivation' ) );
        $this->includes();
    }

    public function includes()
    {
        include_once('includes/infisecure_config.php');
        include_once('includes/infisecure_service.php');
        if ($this->isRequest('admin') ) {
            $this->adminIncludes();
        }
        if ($this->isRequest('frontend') ) {
            $this->frontend_includes();
        }

    }

    public function plugin_activation()
    {
        return true;
    }
    private function isRequest( $type ) {
        switch ( $type ) {
            case 'admin' :
                return is_admin();
            case 'ajax' :
                return defined( 'DOING_AJAX' );
            case 'cron' :
                return defined( 'DOING_CRON' );
            case 'frontend' :
                return ( ! is_admin() || defined( 'DOING_AJAX' ) ) && ! defined( 'DOING_CRON' );
        }
    }

    /**
     * Include required frontend files.
     */
    public function frontend_includes() {
        include_once( 'includes/frontend-scripts.php' );
    }

    public function adminIncludes()
    {
        include_once('includes/setting.php');
    }
    /**
     * Get the plugin url.
     * @return string
     */
    public function plugin_url() {
        return untrailingslashit( plugins_url( '/', __FILE__ ) );
    }
}

function infisecure_plugins_url() {
    return untrailingslashit( plugins_url( '/', __FILE__ ) );
}

new InfiSecure();