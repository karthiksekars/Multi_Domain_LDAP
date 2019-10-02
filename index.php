<?php

error_reporting(E_ALL);
ini_set('display_errors', 'On');

function ad_validate_user($str_user_name = null, $str_password = null) {

    /* LDAP DOMAIN AND IP LIST */
    $arr_ldap_ips = array(
        'DOMAIN 1' => 'DOMAIN 1 IP',
        'DOMAIN 2' => 'DOMAIN 2 IP'
    );

    $err_msg = $error_code = $extended_error = $arr_status = null;

    // SPLIT DOMAIN    
    $arr_domain_string = explode('@', $str_user_name);
    if (empty($arr_domain_string[1])) {
        $err_msg = 'Invalid mail';
    }
    else {
        $str_fqdn = $arr_domain_string[1];
    }

    if (empty($arr_ldap_ips[$str_fqdn])) {
        $err_msg = 'Invalid Domain';
    }
    else {
        $str_ldap_server = $arr_ldap_ips[$str_fqdn];
    }

    if (empty($err_msg)) {

        $user = $str_user_name;
        $pass = stripslashes($str_password);

        $conn = ldap_connect("ldap://" . $str_ldap_server . "/");


        if (!$conn) {
            $err_msg = 'Could not connect to the server';
        }
        else {
            ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);

            $bind = @ldap_bind($conn, $user, $pass);

            ldap_get_option($conn, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error);

            if (!empty($extended_error)) {
                $error_code = explode(',', $extended_error);
                $error_code = $error_code[2];
                $error_code = explode(' ', $error_code);
                $error_code = $error_code[2];
                $error_code = intval($error_code);

                if ($error_code === 532) {
                    $err_msg = 'Unable to login: Password expired';
                }
            }
            elseif ($bind) {
                //determine the LDAP Path from Active Directory details
                $base_dn = array("CN=Users,DC=" . join(',DC=', explode('.', $str_fqdn)),
                    "OU=Users,OU=People,DC=" . join(',DC=', explode('.', $str_fqdn)));

                $result = ldap_search(array($conn, $conn), $base_dn, "(cn=*)");

                if (!count($result)) {
                    $err_msg = ldap_error($conn);
                }
                else {
                    $arr_status = array(
                        'status'  => true,
                        'message' => 'Success'
                    );
                }
            }
        }

        if (empty($err_msg)) {
            $err_msg = ldap_error($conn);
        }

        ldap_close($conn);
    }

    if (empty($arr_status)) {
        $arr_status = array(
            'status'     => false,
            'message'    => $err_msg,
            'error_code' => $error_code
        );
    }
    return $arr_status;
}

$result = ad_validate_user('YOUR EMAIL', 'YOUR PASSWORD');

echo '<pre>';
print_r($result);



?>