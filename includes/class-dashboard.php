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
        if (!in_array($current_tab, array('email', 'ip', 'spf'), true)) {
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
                <a href="<?php echo esc_url($base_url . '&tab=spf'); ?>"
                   class="nav-tab <?php echo $current_tab === 'spf' ? 'nav-tab-active' : ''; ?>">
                    🔐 <?php esc_html_e('SPF Analyzer', 'pointnet-mailguard'); ?>
                </a>
            </nav>

            <!-- Terminal console (hidden on SPF tab) -->
            <?php if ($current_tab !== 'spf'): ?>
            <div id="pn-mailguard-terminal" style="display:none; background:#000; color:#0f0; padding:20px; font-family:monospace; border-radius:5px; margin:20px 0; border:2px solid #333; height:250px; overflow-y:auto; box-shadow: inset 0 0 10px #000;">
                <div id="pn-mailguard-terminal-content"></div>
            </div>
            <?php endif; ?>

            <?php if ($current_tab === 'email'): ?>
                <?php self::render_email_tab($check_email, $alert_email); ?>
            <?php elseif ($current_tab === 'ip'): ?>
                <?php self::render_ip_tab($check_ip, $alert_email); ?>
            <?php else: ?>
                <?php self::render_spf_tab(); ?>
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
                    lines.push({
                        t: '> SPF record...',
                        v: d.spf_status === 'ok'      ? d.spf_record :
                           d.spf_status === 'missing'  ? 'MISSING — no SPF record found' :
                                                         'INVALID — ' + d.spf_record,
                        ok: d.spf_status === 'ok',
                        warn: d.spf_status !== 'ok'
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

    // Appended methods — SPF Analyzer tab

    private static function render_spf_tab() {
        $saved_domain = get_option('pn_mailguard_spf_domain', '');
        ?>
        <div class="card" style="padding:20px; max-width:800px; margin-bottom:20px;">
            <p style="margin:0 0 12px; color:#666;">
                <?php esc_html_e('Enter a domain or email address to run a full SPF record analysis.', 'pointnet-mailguard'); ?>
            </p>
            <div style="display:flex; gap:10px; align-items:center;">
                <input type="text" id="pn-spf-input" value="<?php echo esc_attr($saved_domain); ?>"
                    placeholder="domain.com or email@domain.com" class="regular-text">
                <button type="button" id="pn-spf-analyze-btn" class="button button-primary">
                    <?php esc_html_e('Analyze SPF', 'pointnet-mailguard'); ?>
                </button>
            </div>
        </div>

        <div id="pn-spf-results" style="max-width:800px; display:none;">

            <div id="pn-spf-record-box" style="background:#1e1e2e; color:#a6e3a1; font-family:monospace; font-size:13px; padding:14px 18px; border-radius:5px; word-break:break-all; margin-bottom:16px; border:1px solid #333;"></div>

            <div id="pn-spf-summary" style="display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:20px;"></div>

            <div id="pn-spf-providers" style="margin-bottom:16px; display:none;">
                <strong style="font-size:13px;"><?php esc_html_e('Detected senders:', 'pointnet-mailguard'); ?></strong>
                <span id="pn-spf-providers-list" style="font-size:13px; margin-left:8px;"></span>
            </div>

            <div class="wp-list-table widefat" style="border-radius:5px; overflow:hidden;">
                <table style="width:100%; border-collapse:collapse;">
                    <thead>
                        <tr style="background:#f0f0f0;">
                            <th style="width:16px; padding:10px 8px 10px 14px;"></th>
                            <th style="padding:10px 14px; text-align:left; font-size:12px;"><?php esc_html_e('Check', 'pointnet-mailguard'); ?></th>
                            <th style="padding:10px 14px; text-align:left; font-size:12px; width:110px;"><?php esc_html_e('Result', 'pointnet-mailguard'); ?></th>
                            <th style="padding:10px 14px; text-align:left; font-size:12px;"><?php esc_html_e('Details', 'pointnet-mailguard'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="pn-spf-checks"></tbody>
                </table>
            </div>

            <p style="font-size:12px; color:#999; margin-top:16px;">
                <?php esc_html_e('Need help fixing SPF issues? Contact', 'pointnet-mailguard'); ?>
                <a href="https://www.pointnet.it/" target="_blank">PointNet</a> —
                <?php esc_html_e('email deliverability specialists.', 'pointnet-mailguard'); ?>
            </p>
        </div>

        <div id="pn-spf-error" style="display:none; max-width:800px;"></div>

        <script>
        jQuery(document).ready(function($) {
            var nonce = "<?php echo esc_js(wp_create_nonce('pn_mailguard_ajax_nonce')); ?>";

            $('#pn-spf-analyze-btn').on('click', function() {
                var domain = $('#pn-spf-input').val().trim();
                if (!domain) return;

                var btn = $(this);
                btn.prop('disabled', true).text('<?php echo esc_js(__('Analyzing...', 'pointnet-mailguard')); ?>');
                $('#pn-spf-results').hide();
                $('#pn-spf-error').hide();

                $.post(ajaxurl, {
                    action: 'pn_mailguard_analyze_spf',
                    nonce: nonce,
                    domain: domain
                }, function(res) {
                    btn.prop('disabled', false).text('<?php echo esc_js(__('Analyze SPF', 'pointnet-mailguard')); ?>');

                    if (!res.success) {
                        $('#pn-spf-error')
                            .html('<div class="notice notice-error inline"><p>' + (res.data.message || 'Error') + '</p></div>')
                            .show();
                        return;
                    }

                    var d = res.data;

                    // Record
                    if (d.record) {
                        $('#pn-spf-record-box').text(d.record);
                    } else {
                        $('#pn-spf-record-box').text('<?php echo esc_js(__('No SPF record found.', 'pointnet-mailguard')); ?>');
                    }

                    // Summary cards
                    var summaryColor = d.errors > 0 ? '#d63638' : (d.warnings > 0 ? '#dba617' : '#00a32a');
                    $('#pn-spf-summary').html(
                        spfCard(d.passed,      '<?php echo esc_js(__('passed', 'pointnet-mailguard')); ?>',  '#00a32a') +
                        spfCard(d.warnings,    '<?php echo esc_js(__('warnings', 'pointnet-mailguard')); ?>', '#dba617') +
                        spfCard(d.errors,      '<?php echo esc_js(__('errors', 'pointnet-mailguard')); ?>',   '#d63638') +
                        spfCard(d.dns_lookups, '<?php echo esc_js(__('DNS lookups', 'pointnet-mailguard')); ?>', '#2271b1')
                    );

                    // Providers
                    if (d.providers && d.providers.length > 0) {
                        $('#pn-spf-providers-list').text(d.providers.join(', '));
                        $('#pn-spf-providers').show();
                    } else {
                        $('#pn-spf-providers').hide();
                    }

                    // Checks
                    var rows = '';
                    $.each(d.checks, function(i, check) {
                        var dot, badge, bg;
                        if (check.status === 'ok') {
                            dot   = '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#00a32a;"></span>';
                            badge = '<span style="background:#edfaef;color:#00a32a;font-size:11px;font-weight:600;padding:2px 8px;border-radius:3px;">&#10003; Pass</span>';
                            bg    = i % 2 === 0 ? '#fff' : '#fafafa';
                        } else if (check.status === 'warning') {
                            dot   = '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#dba617;"></span>';
                            badge = '<span style="background:#fff8e5;color:#996800;font-size:11px;font-weight:600;padding:2px 8px;border-radius:3px;">&#9888; Warning</span>';
                            bg    = i % 2 === 0 ? '#fffdf0' : '#fffce8';
                        } else {
                            dot   = '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#d63638;"></span>';
                            badge = '<span style="background:#fbeaea;color:#a30000;font-size:11px;font-weight:600;padding:2px 8px;border-radius:3px;">&#10007; Error</span>';
                            bg    = i % 2 === 0 ? '#fff8f8' : '#fff2f2';
                        }
                        rows += '<tr style="background:' + bg + '; border-top:0.5px solid #e0e0e0;">';
                        rows += '<td style="padding:10px 8px 10px 14px;">' + dot + '</td>';
                        rows += '<td style="padding:10px 14px; font-size:13px; font-weight:600;">' + escHtml(check.title) + '</td>';
                        rows += '<td style="padding:10px 14px;">' + badge + '</td>';
                        rows += '<td style="padding:10px 14px; font-size:12px; color:#555; line-height:1.5;">' + escHtml(check.description) + '</td>';
                        rows += '</tr>';
                    });
                    $('#pn-spf-checks').html(rows);
                    $('#pn-spf-results').show();
                });
            });

            function spfCard(num, label, color) {
                return '<div style="background:#f8f8f8;border-radius:5px;padding:14px;text-align:center;border:1px solid #e0e0e0;">' +
                    '<div style="font-size:24px;font-weight:600;color:' + color + ';">' + num + '</div>' +
                    '<div style="font-size:11px;color:#666;margin-top:3px;">' + label + '</div></div>';
            }

            function escHtml(str) {
                return $('<div>').text(str).html();
            }
        });
        </script>
        <?php
    }

    public static function ajax_analyze_spf() {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized.'));
        }

        $input = isset($_POST['domain']) ? sanitize_text_field($_POST['domain']) : '';
        if (empty($input)) {
            wp_send_json_error(array('message' => __('Please enter a domain or email address.', 'pointnet-mailguard')));
            return;
        }

        if (get_transient('pn_mailguard_spf_lock')) {
            wp_send_json_error(array('message' => __('Please wait 30 seconds before running another analysis.', 'pointnet-mailguard')));
            return;
        }
        set_transient('pn_mailguard_spf_lock', 1, 30);

        update_option('pn_mailguard_spf_domain', $input);

        $result = PN_Mailguard_SPF::analyze($input);

        if (!empty($result['error'])) {
            wp_send_json_error(array('message' => $result['error']));
            return;
        }

        wp_send_json_success($result);
    }
