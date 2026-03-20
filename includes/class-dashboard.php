<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Dashboard
 *
 * Handles all admin UI: tabbed menu page, settings forms, AJAX handlers.
 * Tab 'email' — monitors a mail server via email address and MX lookup.
 * Tab 'ip'    — monitors any IPv4 address directly.
 */
class PN_Mailguard_Dashboard {

    // --- Settings ---

    public static function register_settings() {
        register_setting('pn_mailguard_settings', 'pn_mailguard_check_email', array('sanitize_callback' => 'sanitize_email'));
        register_setting('pn_mailguard_settings', 'pn_mailguard_check_ip',    array('sanitize_callback' => 'sanitize_text_field'));
        register_setting('pn_mailguard_settings', 'pn_mailguard_email_alert', array('sanitize_callback' => 'sanitize_email'));
    }

    public static function save_settings() {
        if (!isset($_POST['pn_mailguard_save_all'])) {
            return;
        }
        check_admin_referer('pn_mailguard_save_action', 'pn_mailguard_nonce');
        if (!current_user_can('manage_options')) {
            wp_die(__('Unauthorized', 'pointnet-mailguard'));
        }

        $tab         = isset($_POST['pn_mailguard_tab']) ? sanitize_key($_POST['pn_mailguard_tab']) : 'email';
        $alert_email = sanitize_email($_POST['pn_mailguard_email_alert']);

        if (!empty($alert_email) && !is_email($alert_email)) {
            add_settings_error('pn_mailguard_messages', 'invalid_alert_email',
                __('Please enter a valid alert email address.', 'pointnet-mailguard'));
            return;
        }

        if ($tab === 'email') {
            $check_email = sanitize_email($_POST['pn_mailguard_check_email']);
            if (empty($check_email) || !is_email($check_email)) {
                add_settings_error('pn_mailguard_messages', 'invalid_check_email',
                    __('Please enter a valid email address to monitor.', 'pointnet-mailguard'));
                return;
            }
            update_option('pn_mailguard_check_email', $check_email);
        } else {
            $check_ip = sanitize_text_field($_POST['pn_mailguard_check_ip']);
            if (empty($check_ip) || !filter_var($check_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                add_settings_error('pn_mailguard_messages', 'invalid_ip',
                    __('Please enter a valid IPv4 address to monitor.', 'pointnet-mailguard'));
                return;
            }
            update_option('pn_mailguard_check_ip', $check_ip);
        }

        update_option('pn_mailguard_email_alert', $alert_email);
        add_settings_error('pn_mailguard_messages', 'settings_saved',
            __('Settings saved.', 'pointnet-mailguard'), 'success');
    }

    // --- Menu ---

    public static function add_menu() {
        add_menu_page(
            'PointNet Mail Guard AI',
            'PointNet Mail Guard AI',
            'manage_options',
            'pn-mailguard',
            array('PN_Mailguard_Dashboard', 'render_page'),
            'dashicons-shield'
        );
    }

    public static function action_links($links) {
        $settings_link = '<a href="' . admin_url('admin.php?page=pn-mailguard') . '">'
            . __('Settings', 'pointnet-mailguard') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    // --- Page render ---

    public static function render_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('Unauthorized', 'pointnet-mailguard'));
        }

        $current_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'email';
        if (!in_array($current_tab, array('email', 'ip'), true)) {
            $current_tab = 'email';
        }

        $base_url    = admin_url('admin.php?page=pn-mailguard');
        $check_email = get_option('pn_mailguard_check_email', '');
        $check_ip    = get_option('pn_mailguard_check_ip', '');
        $alert_email = get_option('pn_mailguard_email_alert', get_option('admin_email'));
        ?>
        <div class="wrap">
            <h1>🛡️ PointNet Mail Guard AI <small>v<?php echo esc_html(PN_MAILGUARD_VERSION); ?></small></h1>

            <?php settings_errors('pn_mailguard_messages'); ?>

            <?php
            $next = wp_next_scheduled('pn_mailguard_daily_scan');
            if ($next) {
                $next_local = get_date_from_gmt(gmdate('Y-m-d H:i:s', $next), 'D d M Y \a\t H:i');
                echo '<div class="notice notice-info inline"><p>'
                    . '🕒 ' . esc_html__('Next automatic scan scheduled for:', 'pointnet-mailguard')
                    . ' <strong>' . esc_html($next_local) . '</strong></p></div>';
            }
            ?>

            <!-- Tab navigation -->
            <nav class="nav-tab-wrapper" style="margin-bottom:20px;">
                <a href="<?php echo esc_url($base_url . '&tab=email'); ?>"
                   class="nav-tab <?php echo $current_tab === 'email' ? 'nav-tab-active' : ''; ?>">
                    📧 <?php esc_html_e('Email Monitor', 'pointnet-mailguard'); ?>
                </a>
                <a href="<?php echo esc_url($base_url . '&tab=ip'); ?>"
                   class="nav-tab <?php echo $current_tab === 'ip' ? 'nav-tab-active' : ''; ?>">
                    🌐 <?php esc_html_e('IP Monitor', 'pointnet-mailguard'); ?>
                </a>
            </nav>

            <!-- Terminal console (shared between tabs) -->
            <div id="pn-mailguard-terminal" style="display:none; background:#000; color:#0f0; padding:20px; font-family:monospace; border-radius:5px; margin:20px 0; border:2px solid #333; height:250px; overflow-y:auto; box-shadow: inset 0 0 10px #000;">
                <div id="pn-mailguard-terminal-content"></div>
            </div>

            <?php if ($current_tab === 'email'): ?>
                <?php self::render_email_tab($check_email, $alert_email); ?>
            <?php else: ?>
                <?php self::render_ip_tab($check_ip, $alert_email); ?>
            <?php endif; ?>

        </div>

        <?php self::render_js($current_tab); ?>
        <?php
    }

    // --- Email tab ---

    private static function render_email_tab($check_email, $alert_email) {
        ?>
        <div class="card" style="padding:20px; max-width:800px;">
            <form method="post">
                <?php wp_nonce_field('pn_mailguard_save_action', 'pn_mailguard_nonce'); ?>
                <input type="hidden" name="pn_mailguard_tab" value="email">
                <table class="form-table">
                    <tr>
                        <th><?php esc_html_e('Email address to monitor', 'pointnet-mailguard'); ?></th>
                        <td>
                            <input type="email" name="pn_mailguard_check_email"
                                value="<?php echo esc_attr($check_email); ?>" class="regular-text">
                            <p class="description">
                                <?php esc_html_e('Enter the email address you send from (e.g. info@yourdomain.com). The plugin will detect your mail server automatically.', 'pointnet-mailguard'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('Alert email', 'pointnet-mailguard'); ?></th>
                        <td>
                            <input type="email" name="pn_mailguard_email_alert"
                                value="<?php echo esc_attr($alert_email); ?>" class="regular-text">
                            <p class="description">
                                <?php esc_html_e('Where to send alerts when problems are detected.', 'pointnet-mailguard'); ?>
                            </p>
                        </td>
                    </tr>
                </table>
                <input type="submit" name="pn_mailguard_save_all" class="button button-primary"
                    value="<?php esc_attr_e('Save Settings', 'pointnet-mailguard'); ?>">
                <?php $scan_ready = !empty($check_email) && is_email($check_email); ?>
                <button type="button" id="pn-mailguard-start-btn" class="button button-secondary"
                    <?php disabled(!$scan_ready); ?>
                    title="<?php echo !$scan_ready ? esc_attr__('Save a valid email address first.', 'pointnet-mailguard') : ''; ?>"
                    style="<?php echo !$scan_ready ? 'opacity:0.4; cursor:not-allowed;' : ''; ?>">
                    <?php esc_html_e('Run Diagnosis Now', 'pointnet-mailguard'); ?>
                </button>
            </form>
        </div>

        <h2><?php esc_html_e('Email Monitor — Diagnostic Logs', 'pointnet-mailguard'); ?></h2>
        <?php self::render_log_table('email'); ?>
        <?php
    }

    // --- IP tab ---

    private static function render_ip_tab($check_ip, $alert_email) {
        ?>
        <div class="card" style="padding:20px; max-width:800px;">
            <form method="post">
                <?php wp_nonce_field('pn_mailguard_save_action', 'pn_mailguard_nonce'); ?>
                <input type="hidden" name="pn_mailguard_tab" value="ip">
                <table class="form-table">
                    <tr>
                        <th><?php esc_html_e('IP address to monitor', 'pointnet-mailguard'); ?></th>
                        <td>
                            <input type="text" name="pn_mailguard_check_ip"
                                value="<?php echo esc_attr($check_ip); ?>" class="regular-text"
                                placeholder="e.g. 1.2.3.4">
                            <p class="description">
                                <?php esc_html_e('Enter any IPv4 address to monitor — your VPS, a mail relay, or any server you manage.', 'pointnet-mailguard'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('Alert email', 'pointnet-mailguard'); ?></th>
                        <td>
                            <input type="email" name="pn_mailguard_email_alert"
                                value="<?php echo esc_attr($alert_email); ?>" class="regular-text">
                            <p class="description">
                                <?php esc_html_e('Where to send alerts when problems are detected.', 'pointnet-mailguard'); ?>
                            </p>
                        </td>
                    </tr>
                </table>
                <input type="submit" name="pn_mailguard_save_all" class="button button-primary"
                    value="<?php esc_attr_e('Save Settings', 'pointnet-mailguard'); ?>">
                <?php $scan_ready = !empty($check_ip) && filter_var($check_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4); ?>
                <button type="button" id="pn-mailguard-start-btn" class="button button-secondary"
                    <?php disabled(!$scan_ready); ?>
                    title="<?php echo !$scan_ready ? esc_attr__('Save a valid IPv4 address first.', 'pointnet-mailguard') : ''; ?>"
                    style="<?php echo !$scan_ready ? 'opacity:0.4; cursor:not-allowed;' : ''; ?>">
                    <?php esc_html_e('Run Diagnosis Now', 'pointnet-mailguard'); ?>
                </button>
            </form>
        </div>

        <h2><?php esc_html_e('IP Monitor — Diagnostic Logs', 'pointnet-mailguard'); ?></h2>
        <?php self::render_log_table('ip'); ?>
        <?php
    }

    // --- Log table ---

    private static function render_log_table($type) {
        ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th width="20%"><?php esc_html_e('Date', 'pointnet-mailguard'); ?></th>
                    <th width="15%"><?php esc_html_e('Status', 'pointnet-mailguard'); ?></th>
                    <th><?php esc_html_e('Technical Details', 'pointnet-mailguard'); ?></th>
                </tr>
            </thead>
            <tbody id="pn-mailguard-log-body"><?php PN_Mailguard_Logger::render_rows($type); ?></tbody>
        </table>
        <?php
    }

    // --- JavaScript ---

    private static function render_js($tab) {
        $action = ($tab === 'ip') ? 'pn_mailguard_start_scan_ip' : 'pn_mailguard_start_scan_email';
        ?>
        <script>
        var pnMailguardNonce = "<?php echo esc_js(wp_create_nonce('pn_mailguard_ajax_nonce')); ?>";

        jQuery(document).ready(function($) {
            $('#pn-mailguard-start-btn').on('click', function() {
                var btn     = $(this);
                var content = $('#pn-mailguard-terminal-content');

                btn.prop('disabled', true).text('<?php echo esc_js(__('Running...', 'pointnet-mailguard')); ?>');
                $('#pn-mailguard-terminal').slideDown();
                content.html('<p>> Starting PointNet Mail Guard AI...</p>');

                $.post(ajaxurl, { action: '<?php echo esc_js($action); ?>', nonce: pnMailguardNonce }, function(res) {
                    if (!res.success) {
                        var msg = (res.data && res.data.message) ? res.data.message : 'Scan failed.';
                        content.append('<p style="color:#f33">> ERROR: ' + msg + '</p>');
                        btn.prop('disabled', false).text('<?php echo esc_js(__('Run Diagnosis Now', 'pointnet-mailguard')); ?>');
                        return;
                    }

                    var d     = res.data;
                    var lines = [];

                    <?php if ($tab === 'email'): ?>
                    lines.push({ t: '> Email domain...',     v: d.domain,   ok: true });
                    lines.push({ t: '> Mail server (MX)...', v: d.mx_host + ' (' + d.mx_ip + ')', ok: true });
                    lines.push({
                        t: '> Server setup...',
                        v: d.shared_server ? 'SHARED — mail and WordPress on same server' : 'SEPARATE — dedicated mail server',
                        ok: !d.shared_server,
                        warn: d.shared_server
                    });
                    <?php else: ?>
                    lines.push({ t: '> IP address...', v: d.ip, ok: true });
                    <?php endif; ?>

                    lines.push({
                        t: '> PTR (reverse DNS)...',
                        v: d.ptr_warning ? d.ptr + ' [WARNING]' : d.ptr,
                        ok: !d.ptr_warning
                    });

                    Object.entries(d.dnsbl).forEach(function(entry) {
                        lines.push({ t: '> Blacklist ' + entry[0] + '...', v: entry[1], ok: entry[1] === 'CLEAN' });
                    });

                    var i       = 0;
                    var printer = setInterval(function() {
                        if (i < lines.length) {
                            var color;
                            if (lines[i].warn) {
                                color = '#ff0';
                            } else {
                                color = lines[i].ok ? '#0f0' : '#f33';
                            }
                            content.append('<p style="color:' + color + '">' + lines[i].t + ' [' + lines[i].v + ']</p>');
                            $('#pn-mailguard-terminal').scrollTop($('#pn-mailguard-terminal')[0].scrollHeight);
                            i++;
                        } else {
                            content.append('<p style="color:#fff; border-top:1px solid #333; margin-top:10px;">> <?php echo esc_js(__('DIAGNOSIS COMPLETE.', 'pointnet-mailguard')); ?></p>');
                            btn.prop('disabled', false).text('<?php echo esc_js(__('Run Diagnosis Now', 'pointnet-mailguard')); ?>');
                            var refreshAction = '<?php echo esc_js($tab === 'ip' ? 'pn_mailguard_refresh_logs_ip' : 'pn_mailguard_refresh_logs_email'); ?>';
                            $.post(ajaxurl, { action: refreshAction, nonce: pnMailguardNonce }, function(r) {
                                if (r.success) $('#pn-mailguard-log-body').html(r.data);
                            });
                            clearInterval(printer);
                        }
                    }, 400);
                });
            });
        });
        </script>
        <?php
    }

    // --- AJAX handlers ---

    public static function ajax_start_scan_email() {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized.'));
        }

        $email = get_option('pn_mailguard_check_email', '');
        if (empty($email) || !is_email($email)) {
            wp_send_json_error(array('message' => __('No valid email address configured. Please save your settings first.', 'pointnet-mailguard')));
            return;
        }

        if (get_transient('pn_mailguard_scan_lock')) {
            wp_send_json_error(array('message' => __('Please wait 30 seconds before running another scan.', 'pointnet-mailguard')));
            return;
        }
        set_transient('pn_mailguard_scan_lock', 1, 30);

        $data = PN_Mailguard_Scanner::run_email($email);
        PN_Mailguard_Logger::save($data, 'email');
        PN_Mailguard_Mailer::maybe_send($data, 'email');

        if (!empty($data['error'])) {
            wp_send_json_error(array('message' => $data['error']));
            return;
        }
        wp_send_json_success($data);
    }

    public static function ajax_start_scan_ip() {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized.'));
        }

        $ip = get_option('pn_mailguard_check_ip', '');
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            wp_send_json_error(array('message' => __('No valid IP address configured. Please save your settings first.', 'pointnet-mailguard')));
            return;
        }

        if (get_transient('pn_mailguard_scan_lock')) {
            wp_send_json_error(array('message' => __('Please wait 30 seconds before running another scan.', 'pointnet-mailguard')));
            return;
        }
        set_transient('pn_mailguard_scan_lock', 1, 30);

        $data = PN_Mailguard_Scanner::run_ip($ip);
        PN_Mailguard_Logger::save($data, 'ip');
        PN_Mailguard_Mailer::maybe_send($data, 'ip');

        if (!empty($data['error'])) {
            wp_send_json_error(array('message' => $data['error']));
            return;
        }
        wp_send_json_success($data);
    }

    public static function ajax_refresh_logs_email() {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }
        ob_start();
        PN_Mailguard_Logger::render_rows('email');
        wp_send_json_success(ob_get_clean());
    }

    public static function ajax_refresh_logs_ip() {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }
        ob_start();
        PN_Mailguard_Logger::render_rows('ip');
        wp_send_json_success(ob_get_clean());
    }
}
