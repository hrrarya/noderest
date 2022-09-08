<?php

// plugin activation hook
register_activation_hook(__FILE__, 'mytable_activation_function');

// callback function to create table
function mytable_activation_function()
{
    global $wpdb;

    if ($wpdb->get_var("show tables like '" . owt_create_my_table() . "'") != owt_create_my_table()) {

        $mytable = 'CREATE TABLE `' . owt_create_my_table() . '` (
                            `id` int(11) NOT NULL AUTO_INCREMENT,
                            `name` varchar(100) NOT NULL,
                            `email` varchar(50) NOT NULL,
                            `status` int(11) NOT NULL DEFAULT "1",
                            `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            PRIMARY KEY (`id`)
                          ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;';

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($mytable);
    }
}

// returns table name
function owt_create_my_table()
{
    global $wpdb;
    return $wpdb->prefix . "mytable";
}
