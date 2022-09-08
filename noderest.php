<?php
/**
 * Plugin Name: Node Rest API
 * Description: Basic Rest API implementation
 * Author: Hridoy Mozumder
 * Author URI: https://github.com/hrrarya
 * Version: 0.1
 * Plugin URI: https://github.com/hrrarya/noderest-api-with-jwt
 */

if(!defined('ABSPATH')) {
    die();
}

// Define Constant
define('NODEREST_PRIVATE_KEY', get_option('noderest_secrect_key'));



require_once(plugin_dir_path(__FILE__) . '/vendor/autoload.php');


use Nowakowskir\JWT\JWT;
use Nowakowskir\JWT\TokenDecoded;
use Nowakowskir\JWT\TokenEncoded;
use Hridoy\Noderest\Helper;


if( !function_exists('noderest__helper')) {
    add_action('wp_ajax_nopriv_noderest__helper', 'noderest__helper');
    function noderest__helper() {
        echo 'hridoy';
        wp_die();
    }
}

if( !function_exists('noderest__is_token_valid')) {
    add_action('wp_ajax_nopriv_is_token_valid', 'noderest__is_token_valid');

    function noderest__is_token_valid() {
        $token = '';
        

        $headers = getallheaders();

        if (array_key_exists('Authorization', $headers)) {
            $token = explode(" ", $headers['Authorization'])[1];
            
            $tokenEncoded = new TokenEncoded($token);
            
            try {
                $tokenEncoded->validate(NODEREST_PRIVATE_KEY, JWT::ALGORITHM_HS256);

                return wp_send_json_success(array(
                    'message' => 'Authorized User'
                ), 200); 
            }catch(Exception $e) {
               return wp_send_json_error(array(
                    'error' => $e->getMessage()
                ), 401);
            }

        }

        return;
    }
}

if( !function_exists( 'noderest__add_table' ) ) {
    function noderest__add_table() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'noderest_user_login';

        if ($wpdb->get_var("show tables like '" . $table_name . "'") != $table_name) {

            $noderest_user_table = 'CREATE TABLE `' . $table_name . '` (
                                `id` int(11) NOT NULL AUTO_INCREMENT,
                                `username` varchar(100) NOT NULL,
                                `status` int(11) NOT NULL DEFAULT "1",
                                `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                `expires_in` timestamp NULL,
                                PRIMARY KEY (`id`)
                              ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;';

            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            dbDelta($noderest_user_table);
        }

    }
}



// Login through ajax request and get logged user data
if( !function_exists('noderest__login') ) {
    add_action('wp_ajax_nopriv_noderest__login', 'noderest__login');

    /**
     * Returns json web token with user information
     * 
     * @return;
     */

    function noderest__login() {
        $username = isset($_POST['username']) ? sanitize_text_field($_POST['username']) : '';
        $password = isset($_POST['password']) ? sanitize_text_field($_POST['password']) : '';

        // $username = 'arya';
        // $password = 'gpgdmw';


        $user = wp_authenticate($username, $password);
        
        
        if( $user->data->ID) {
            
            $isExists = Helper::isExists($user->data->user_login);

            $expire_in = '';


            if('' !== $isExists){ 
               $expire_in = $isExists;
            }elseif( '' === $isExists) {
                Helper::delete_user($user->data->user_login);
                $expire_in = time() + (60 * 3);
            }

            // $user = get_user_data($user->data->ID);


            $user_arr = array(
                'id'    => $user->data->ID,
                'username'    => $user->data->user_login,
                'roles'     => $user->roles
            );
            
            

            $tokenDecoded = new TokenDecoded(array(
                'payload_key' => $user_arr,
                'exp'         => $expire_in,
            ));
            $tokenEncoded = $tokenDecoded->encode(NODEREST_PRIVATE_KEY, JWT::ALGORITHM_HS256);




            if($tokenEncoded->validate(NODEREST_PRIVATE_KEY, JWT::ALGORITHM_HS256)) {
                $user_arr['token'] = $tokenEncoded->toString();
            }            

            wp_send_json_success($user_arr, 200);
            

            // if( '' === $isExists && noderest__add_userdata($username, $expire_in)) {
            //     return wp_send_json_success($user_arr, 200);
            // }else {
            //     return wp_send_json_success($user_arr, 200);
            // }

        }elseif( $user->errors ) {
            $error  = $user->errors;
            return wp_send_json_error(array(
                'errors' => $error
            ), 403);
        }
        
        wp_die();
    }
 }


// Register through ajax request

if( !function_exists('noderest__register') ) {
    add_action('wp_ajax_nopriv_noderest__register', 'noderest__register');

    function noderest__register() {
        $username = isset($_POST['username']) ? sanitize_text_field($_POST['username']) : '';
        $password = isset($_POST['password']) ? sanitize_text_field($_POST['password']) : '';
        $email    = isset($_POST['email']) ? sanitize_email($_POST['email']) : '';




        // check_ajax_referer( 'ajax-register-nonce', 'security' );

        // Nonce is not checked, because we will get request from JavaScript framework app. For now, I don't know how to use nonce in JavaScript framework

        if( !empty($username) && !empty($email) && !empty($password) ) {

            $info = array();
            $info['user_nicename'] = $info['nickname'] = $info['display_name'] = $info['first_name'] = $info['user_login'] = $username ;
            $info['user_pass'] = $password;
            $info['user_email'] = $email;
            
            // Register the user
            $user_register = wp_insert_user( $info );

            if ( is_wp_error($user_register) ){ 
                $error  = $user_register->get_error_codes() ;

                if(in_array('empty_user_login', $error))
                    return wp_send_json_error(
                        array(
                            'loggedin'=>false, 
                            'error'=>array(
                                    'message' => __($user_register->get_error_message('empty_user_login'))
                            )
                        ), 422);
                elseif(in_array('existing_user_login',$error))
                    return wp_send_json_error(
                        array(
                            'loggedin'=>false,
                            'error'=>array(
                                    'message'=>__('This username is already registered.')
                                )
                        ), 409);
                elseif(in_array('existing_user_email',$error))
                return wp_send_json_error(
                    array(
                        'loggedin'=>false, 
                        'error'=>array(
                                'message'=>__('This email address is already registered.')
                            )
                    ), 409);
            } else {
              return wp_send_json_success(
                array(
                    'user_id'       => $user_register,
                    'user_login'    => $info['nickname'],
                    'user_email'    => $info['user_email'],
                    'success'       => array(
                            'message'       => 'User created successfully'
                    )
                ), 201);
            }
        }

    die();
    }
}

// Insert logged user data into database 
if( !function_exists('noderest__add_userdata' ) ) {
    // $username, $password, $expires_in
    function noderest__add_userdata($username, $expires_in) {
        global $wpdb;

        // $username = 'arya';
        // $password = 'gpgdmw';
        // $expires_in = time() + (60 * 5);

        $table_name = $wpdb->prefix . 'noderest_user_login';

        if( !empty($username) && !empty($expires_in) ) {
            $data = array(
                'username'  => $username,
                'status'    => 1,
                'expires_in'  => date("Y-m-d H:i:s", $expires_in),
            );

        
            if($wpdb->insert($table_name, $data)) return true;
        }


        return false;
    }
}

// Adding wp_options
if(!function_exists('noderest__add_credentials')) {

    function noderest__add_credentials() {
        add_option('noderest_secrect_key', 'private');
        add_option('noderest_enc_dec_iv', '1234567891011121');
        noderest__add_table();
    }

    register_activation_hook(__FILE__, 'noderest__add_credentials');
}

// Allowing only selected address to get the data
if(!function_exists('noderest__handle_preflight')) {
    add_action('init', 'noderest__handle_preflight');
    function noderest__handle_preflight() {
        $origin = get_http_origin();
        if ($origin === 'http://localhost:3000') {
            header("Access-Control-Allow-Origin: $origin");
            header("Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE");
            header("Access-Control-Allow-Credentials: true");
            header('Access-Control-Allow-Headers: Origin, X-Requested-With, X-WP-Nonce, Content-Type, Accept, Authorization');
            if ('OPTIONS' == $_SERVER['REQUEST_METHOD']) {
                status_header(200);
                exit();
            }
        }
    }
}

// Rejecting requests from non allowed adresses
if( !function_exists('noderest__rest_filter_incoming_connections')) {
    add_filter('rest_authentication_errors', 'noderest__rest_filter_incoming_connections');
    function noderest__rest_filter_incoming_connections($errors) {
        $request_server = $_SERVER['REMOTE_ADDR'];
        $origin = get_http_origin();
        if ($origin !== 'http://localhost:3000') return new WP_Error('forbidden_access', $origin, array(
            'status' => 403
        ));
        return $errors;
    }
}


