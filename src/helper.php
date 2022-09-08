<?php

namespace Hridoy\Noderest;

use Nowakowskir\JWT\TokenEncoded;

class Helper {

	public function encrypt($string) {

		// Storingthe cipher method 
		$ciphering = "AES-128-CTR";

		// Using OpenSSl Encryption method 
		$iv_length = openssl_cipher_iv_length($ciphering);
		$options   = 0;

		// Non-NULL Initialization Vector for encryption 
		$encryption_iv = get_option('noderest_enc_dec_iv');

		// Storing the encryption key 
		$encryption_key = get_option('noderest_secret_key');

		// Using openssl_encrypt() function to encrypt the data 
		$encryption = openssl_encrypt($string, $ciphering, $encryption_key, $options, $encryption_iv);

		return $encryption;
	}

	public function decrypt($encryption) {
		$ciphering = "AES-128-CTR";
		$options = 0;
		// Non-NULL Initialization Vector for decryption 
		$decryption_iv = get_option('noderest_enc_dec_iv');

		// Storing the decryption key 
		$decryption_key = get_option('noderest_secret_key');

		// Using openssl_decrypt() function to decrypt the data 
		$decryption = openssl_decrypt($encryption, $ciphering, $decryption_key, $options, $decryption_iv);

		// return the decrypted string 
		return $decryption;
	}

	public static function isTokenExpired($token) {
        // $tokenEncoded = new TokenEncoded($token);
        // $header = $tokenEncoded->decode()->getPayload();

        // return $header['exp'] < time();
        $tokenEncoded = new TokenEncoded($token);
            
        try {
            $tokenEncoded->validate('private', JWT::ALGORITHM_HS256);

            // return wp_send_json_error(array(
            //     'messa' => $e->getMessage()
            // ), 200); 
        }catch(Exception $e) {
           return wp_send_json_error(array(
                'error' => $e->getMessage()
            ), 401);
        }
    }


    public static function isExists($user_login) {
    	global $wpdb;

    	$table_prefix = $wpdb->prefix;
    	$results = $wpdb->get_results($wpdb->prepare("SELECT expires_in FROM {$table_prefix}noderest_user_login WHERE username=%s LIMIT 1", $user_login));

    	if(count($results) == 1) {
    		$timestamp = strtotime($results['0']->expires_in);
    		return ($timestamp > time()) ? $timestamp : '';
    	}
    	return '';
    }

    public static function delete_user( $user_login ) {
    	global $wpdb;

    	$table_prefix = $wpdb->prefix;

    	$results = $wpdb->query($wpdb->prepare("DELETE FROM {$table_prefix}noderest_user_login WHERE username=%s", $user_login));

    	return $results;
    }

}
