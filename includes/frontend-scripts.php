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
class Infisecure_Frontend_Scripts {

    /**
     * Hook in methods.
     */
    public static function init() {
        add_action( 'wp_enqueue_scripts', array( __CLASS__, 'load_scripts' ) );
    }

    /**
     * Register/queue frontend scripts.
     */
    public static function load_scripts() {

        self::enqueue_script(
            'infisecure', 'https://cdn.infisecure.com/assets/js/infisecure.js'
        );
    }

    private static function enqueue_script( $handle, $path ='') {
        wp_enqueue_script($handle, $path);
        $lnisupid = "";
        $request_type = 1;
        $requested_by = "";
        try {
            $infiSecureResponse = infisecureCompliance($lnisupid, $request_type, $requested_by);
        }catch(Exception $e) {

        }
        if($infiSecureResponse->statusCode && ($infiSecureResponse->statusCode == 1000)) {
            wp_add_inline_script(
                $handle,
                "var upid = '{$infiSecureResponse->upid}';" ,
                'before'
            );
            wp_add_inline_script(
                $handle,
                "var host = '{$infiSecureResponse->host}';" ,
                'before'
            );

        }

    }


}

Infisecure_Frontend_Scripts::init();