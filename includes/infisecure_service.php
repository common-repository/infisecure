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
class Infisecure_lnisRequest
{
    public $lnisa1 = "";
    public $lnisa2 = "";
    public $lnisa3 = "";
    public $lnisa4 = "";
    public $lnisa5 = "";
    public $lnisa6 = "";
    public $lnisa7 = "";
    public $lnisa8 = "";
    public $lnisa9 = "";
    public $lnisa10 = "";
    public $lnisa11 = "";
    public $lnisa12 = "";
    public $lnisa13 = "";
    public $lnisa14 = "";
    public $lnisa15 = "";
    public $lnisa16 = "";
    public $lnisa17 = "";
}

class Infisecure_lnisReponse
{
    public $upid = "";
    public $statusCode = "";
    public $message = "";
    public $host = "";
}

class Infisecure_Reponse_Codes
{
    public $RESPONSE_EXCEPTION = -1;
    public $RESPONSE_STATIC_RESOURCE = -2;
}

class Infisecure_Server_Response
{
    public $statusCode = "";
    public $message = "";
}

function infisecureCompliance($requestType, $requestedBy)
{
    $current_time = time();
    $current_time_milli = round(microtime(true) * 1000);
    $lnis_request = new Infisecure_lnisRequest();
    $lnis_reponse = new Infisecure_lnisReponse();
    $infisecure_codes = new Infisecure_Reponse_Codes();
    $infiserver_response = new Infisecure_Server_Response();
    $config_data = new Infisecure_Config();

    $lnisac0 = 0;
    $lniscc7 = 7;
    $lnisec10 = 10;
    $lnisgc20 = 20;

    $minNumber = 1000000001;
    $maxNumber = 9999999999;

    $cookie_expire_time_high = $current_time + 3600*24*365*1;
    $cookie_expire_time_low = $current_time + 3600*3;

    $infisecure_domain = $config_data->lnis_infisecure_domain;
    $infisecure_api_url = $config_data->lnis_url_scheme.'://'. infisecure_get_host_ip($infisecure_domain) .$config_data->lnis_infisecure_api_path;

    if(isset($_COOKIE["__utm_is1"]))
    {
        $lnis_request->lnisa11 = $_COOKIE["__utm_is1"];
        setcookie("__utm_is1", $lnis_request->lnisa11, $cookie_expire_time_high, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);

        if(isset($_COOKIE["__utm_is2"]) && isset($_COOKIE["__utm_is3"]) && isset($_COOKIE["__utm_is4"]))
        {
            $lnis_request->lnisa12 = $_COOKIE["__utm_is2"];
            setcookie("__utm_is2", $lnis_request->lnisa12, $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);

            if (is_numeric($_COOKIE["__utm_is4"]))
            {
                $lnis_request->lnisa14 = (string)($_COOKIE["__utm_is4"] - 329619);
                setcookie("__utm_is4", (string)($current_time_milli + 329619), $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);
            }
            else
            {
                $lnis_request->lnisa14 = "-1";
                setcookie("__utm_is4", "-1", $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);
            }

            $lnisa13 = $_COOKIE["__utm_is3"];
            $lnisa13_parts = explode('.', $lnisa13);
            if (count($lnisa13_parts) == 3)
            {
                $page_multiplier = $lnisa13_parts[0];
                $page_number = $lnisa13_parts[2];
                if (is_numeric($page_number))
                    $page_number = (string)((int)$page_number + 1);

                if (strlen($page_multiplier) > 20) {
                    $incremented_value = (int)substr($page_multiplier,$lnisec10,strlen($page_multiplier)-$lnisgc20);
                    $lnisa13 = (string)mt_rand($minNumber, $maxNumber).(string)($incremented_value+$lniscc7).(string)mt_rand($minNumber, $maxNumber).".".$lnis_request->lnisa14.".".$page_number;
                }
                else
                {
                    $lnisa13 = "010100000000000000000-0000000000-0";
                }

                $lnis_request->lnisa13 = $lnisa13;
                setcookie("__utm_is3", $lnisa13, $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);
            }
            else
            {
                $lnis_request->lnisa13 = "010100000000000000000-0000000000-0";
                setcookie("__utm_is3", "010100000000000000000-0000000000-0", $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);
            }
        }
        else
        {
            $lnisa13 = (string)mt_rand($minNumber, $maxNumber).(string)($lnisac0).(string)mt_rand($minNumber, $maxNumber).'.'.$current_time_milli.'.1';
            setcookie("__utm_is2", $current_time_milli, $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);
            setcookie("__utm_is3", $lnisa13, $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);
            setcookie("__utm_is4", (string)($current_time_milli + 329619), $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);
            $lnis_request->lnisa12 = $current_time_milli;
            $lnis_request->lnisa13 = $lnisa13;
            $lnis_request->lnisa14 = $current_time_milli;
        }


    }
    else
    {
        $lnisa11 = "a11-".(string)infisecure_generate_uid();
        $lnisa13 = (string)mt_rand($minNumber, $maxNumber).(string)($lnisac0).(string)mt_rand($minNumber, $maxNumber).'.'.$current_time_milli.'.1';
        setcookie("__utm_is1", $lnisa11, $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false ,true);
        setcookie("__utm_is2", $current_time_milli, $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);
        setcookie("__utm_is3", $lnisa13, $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);
        setcookie("__utm_is4", (string)($current_time_milli + 329619), $cookie_expire_time_low, $config_data->lnis_cookie_path, $config_data->lnis_cookie_domain, false, true);
        $lnis_request->lnisa11 = $lnisa11;
        $lnis_request->lnisa12 = $current_time_milli;
        $lnis_request->lnisa13 = $lnisa13;
        $lnis_request->lnisa14 = $current_time_milli;
    }

    $lnis_request->lnisa1 = $config_data->lnis_sub_code;
    $lnisUpid = substr($config_data->lnis_sub_code,0,5)."-".(string)infisecure_generate_uid();
    $lnis_request->lnisa2 = $lnisUpid;
    $lnis_request->lnisa3 = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
    $lnis_request->lnisa4 = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    $lnis_request->lnisa5 = isset($_COOKIE[$config_data->lnis_session_parameter]) ? $_COOKIE[$config_data->lnis_session_parameter] : '';
    if(isset($_SERVER[$config_data->lnis_ip_parameter])){
        $lnis_request->lnisa6 = $_SERVER[$config_data->lnis_ip_parameter];
    }else{
        $lnis_request->lnisa6 = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    }
    $lnis_request->lnisa7 = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $lnis_request->lnisa8 = $requestType;
    $lnis_request->lnisa9 = $requestedBy;
    $lnis_request->lnisa10 = $current_time_milli;
    $lnis_request->lnisa15 = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
    $lnis_request->lnisa16 = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
    $lnis_request->lnisa17 = '';
    $post_request_json = json_encode($lnis_request);

    $lnis_reponse->upid =$lnisUpid;
    $lnis_reponse->host = $infisecure_domain;

    if ($config_data->async_http_post == '1')
    {
        infisecure_execute_post_async($infisecure_api_url, $post_request_json);
        $infiserver_response->statusCode = "1000";
        $infiserver_response->message = "success";
    }
    else
    {
        $infiserver_response = infisecure_execute_post($infisecure_api_url, $post_request_json, $config_data->lnis_timeout_value);
    }


    $lnis_reponse->statusCode = $infiserver_response->statusCode;
    $lnis_reponse->message = $infiserver_response->message;

    return $lnis_reponse;
}

function infisecure_execute_post_async($request_url, $payload)
{
    $cmd = "curl -X POST -H 'Content-Type: application/json' -H 'Content-Language: en-US' -H 'Content-Encoding: UTF-8' --connect-timeout 1 -m 1";
    $cmd .= " -d '" . $payload . "' " . "'" . $request_url . "'";
    $cmd .= " > /dev/null 2>&1 &";
    exec($cmd, $output, $exit);
    return $exit == 0;
}

function infisecure_execute_post($request_url, $payload, $timeout)
{
    try {
        $infiserver_response = new Infisecure_Server_Response();
        $infisecure_codes = new Infisecure_Reponse_Codes();
        $config_data = new Infisecure_Config();
        $args = array(
            'body' => $payload,
            'timeout' => $timeout,
            'redirection' => '5',
            'httpversion' => '1.0',
            'blocking' => true,
            'headers' => array(
                'Content-Type: application/json',
                'Content-Language: en-US',
                'Content-Encoding: UTF-8',
                'X-API-Key: '.(string)$config_data->lnis_api_key
            ),
            'cookies' => array()
        );
        $response = wp_remote_post($request_url, $args);
        if ( is_wp_error( $response ) ) {
            // If the request has failed, show the error message
            $infiserver_response->statusCode = $infisecure_codes->RESPONSE_EXCEPTION;
            $infiserver_response->message = $response->get_error_message();
        } else {
            $content = wp_remote_retrieve_body($response);
            $decoded_object = json_decode($content);
            $infiserver_response->statusCode = $decoded_object->{'statusCode'};
            $infiserver_response->message = $decoded_object->{'message'};
        }

    } catch (Exception $e) {
    }

    return $infiserver_response;
}

function infisecure_generate_uid() {
    return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
        mt_rand( 0, 0xffff ),
        mt_rand( 0, 0x0fff ) | 0x4000,
        mt_rand( 0, 0x3fff ) | 0x8000,
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
    );
}

function infisecure_get_host_ip($host)
{
    /*Initialize variables*/
    $result = "";						//cache result (IP)
    $cltime = 0;						//cache loaded time (last loaded time)
    $ttl = 3600;						//ttl for IP validity
    $filepath = "/dev/shm/infisecure_ns_cache";	//path of the cache file

    $config_data = new Infisecure_Config();
    $ttl = $config_data->lnis_dns_domain_ttl;
    $filepath = $config_data->lnis_dns_domain_cache . 'infisecure_ns_cache';

    if($ttl == -1)
    {
        return $host;
    }
    /*file doesnt exist or not accesible*/
    if(!file_exists($filepath))
    {
        $ip = infisecure_load_ip($host,$filepath);
    }
    /*file exists*/
    else
    {
        $rfile = fopen($filepath, "r");
        $result = fread($rfile,filesize($filepath));
        fclose($rfile);
        $cltime = filemtime($filepath);
        /*file exists with no content*/
        if(!$result || !$cltime)
        {
            $ip = infisecure_load_ip($host,$filepath);
        }
        else
        {
            $life=time()-$cltime;
            /*file exists with content but the value has expired*/
            if($life>$ttl)
            {
                $ip = infisecure_load_ip($host,$filepath);
            }
            /*value has not expired*/
            else
            {
                $ip = $result;
            }
        }
    }
    return $ip;
}

function infisecure_load_ip($host,$filepath)
{
    $ip = gethostbyname($host);
    $wfile = fopen($filepath, "w");
    fwrite($wfile, $ip);
    fclose($wfile);
    return $ip;
}
?>
