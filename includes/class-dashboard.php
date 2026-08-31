<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Dashboard
 *
 * Admin UI: 3 tabs — Dashboard, DNS Tools, Settings.
 * All AJAX handlers are in this class.
 */
class PN_Mailguard_Dashboard {

    // -------------------------------------------------------------------------
    // Settings
    // -------------------------------------------------------------------------

    public static function register_settings(): void {
        register_setting('pn_mailguard_settings', 'pn_mailguard_check_email',   ['sanitize_callback' => 'sanitize_email']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_check_ip',      ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_email_alert',   ['sanitize_callback' => 'sanitize_email']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_dkim_selector', ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_gemini_key',    ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_gemini_model',  ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_alert_level',     ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_uninstall_cleanup', ['sanitize_callback' => 'sanitize_text_field']);

        // IMAP settings
        register_setting('pn_mailguard_settings', 'pn_mailguard_imap_host',         ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_imap_port',         ['sanitize_callback' => 'absint']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_imap_encryption',   ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_imap_username',     ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_imap_password',     ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_imap_mailbox',      ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_imap_auto_fetch',   ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('pn_mailguard_settings', 'pn_mailguard_imap_action_after', ['sanitize_callback' => 'sanitize_text_field']);
    }

    public static function save_settings(): void {
        if (!isset($_POST['pn_mailguard_save_settings'])) return;
        check_admin_referer('pn_mailguard_save_action', 'pn_mailguard_nonce');
        if (!current_user_can('manage_options')) wp_die(esc_html__('Unauthorized', 'pointnet-mailguard'));

        // Save onboarding / monitor fields only if present in the request.
        // This prevents the Advanced tab from clearing monitor data.
        if (isset($_POST['pn_mailguard_check_email'])) {
            $check_email = sanitize_email(wp_unslash($_POST['pn_mailguard_check_email']));
            if (!empty($check_email) && !is_email($check_email)) {
                add_settings_error('pn_mailguard_messages', 'invalid_email', __('Please enter a valid email address to monitor.', 'pointnet-mailguard'), 'error');
                return;
            }
            update_option('pn_mailguard_check_email', $check_email);
        }

        if (isset($_POST['pn_mailguard_check_ip'])) {
            $check_ip = sanitize_text_field(wp_unslash($_POST['pn_mailguard_check_ip']));
            if (!empty($check_ip) && !filter_var($check_ip, FILTER_VALIDATE_IP)) {
                add_settings_error('pn_mailguard_messages', 'invalid_ip', __('Please enter a valid IPv4 or IPv6 address.', 'pointnet-mailguard'), 'error');
                return;
            }
            update_option('pn_mailguard_check_ip', $check_ip);
        }

        if (isset($_POST['pn_mailguard_email_alert'])) {
            $alert_email = sanitize_email(wp_unslash($_POST['pn_mailguard_email_alert']));
            if (!empty($alert_email) && !is_email($alert_email)) {
                add_settings_error('pn_mailguard_messages', 'invalid_alert_email', __('Please enter a valid alert email address.', 'pointnet-mailguard'), 'error');
                return;
            }
            if (!empty($alert_email)) {
                update_option('pn_mailguard_email_alert', $alert_email);
            }
        }

        // Save alert notification level
        if (isset($_POST['pn_mailguard_alert_level'])) {
            $alert_level = sanitize_text_field(wp_unslash($_POST['pn_mailguard_alert_level']));
            if (in_array($alert_level, ['all', 'errors', 'none'], true)) {
                update_option('pn_mailguard_alert_level', $alert_level);
            }
        }

        // Save DKIM selector if present in POST (from onboarding or advanced tab)
        if (isset($_POST['pn_mailguard_dkim_selector'])) {
            $dkim_selector = sanitize_text_field(wp_unslash($_POST['pn_mailguard_dkim_selector']));
            update_option('pn_mailguard_dkim_selector', $dkim_selector);
        }
        if (isset($_POST['pn_mailguard_gemini_model'])) {
            $gemini_model = sanitize_text_field(wp_unslash($_POST['pn_mailguard_gemini_model']));
            update_option('pn_mailguard_gemini_model', $gemini_model);
        }

        // Encrypt Gemini API key before storing in the database if present in POST.
        if (isset($_POST['pn_mailguard_gemini_key'])) {
            $submitted_key = sanitize_text_field(wp_unslash($_POST['pn_mailguard_gemini_key']));
            if (empty($submitted_key)) {
                delete_option('pn_mailguard_gemini_key');
            } elseif ($submitted_key !== '********') {
                $gemini_key = PN_Mailguard_Crypto::encrypt($submitted_key);
                update_option('pn_mailguard_gemini_key', $gemini_key);
            }
        }

        // Save IMAP settings if present
        if (isset($_POST['pn_mailguard_imap_host'])) {
            update_option('pn_mailguard_imap_host', sanitize_text_field(wp_unslash($_POST['pn_mailguard_imap_host'])));
            update_option('pn_mailguard_imap_port', absint($_POST['pn_mailguard_imap_port'] ?? 993));
            update_option('pn_mailguard_imap_encryption', sanitize_text_field(wp_unslash($_POST['pn_mailguard_imap_encryption'] ?? 'ssl')));
            update_option('pn_mailguard_imap_username', sanitize_text_field(wp_unslash($_POST['pn_mailguard_imap_username'] ?? '')));
            update_option('pn_mailguard_imap_mailbox', sanitize_text_field(wp_unslash($_POST['pn_mailguard_imap_mailbox'] ?? 'INBOX')));
            update_option('pn_mailguard_imap_action_after', sanitize_text_field(wp_unslash($_POST['pn_mailguard_imap_action_after'] ?? 'delete')));

            $auto_fetch = empty($_POST['pn_mailguard_imap_auto_fetch']) ? '0' : '1';
            update_option('pn_mailguard_imap_auto_fetch', $auto_fetch);

            if ($auto_fetch === '1') {
                if (!wp_next_scheduled('pn_mailguard_fetch_reports_cron')) {
                    wp_schedule_event(time(), 'hourly', 'pn_mailguard_fetch_reports_cron');
                }
            } else {
                $imap_ts = wp_next_scheduled('pn_mailguard_fetch_reports_cron');
                if ($imap_ts) {
                    wp_unschedule_event($imap_ts, 'pn_mailguard_fetch_reports_cron');
                }
            }

            $submitted_imap_pass = wp_unslash($_POST['pn_mailguard_imap_password'] ?? '');
            if (empty($submitted_imap_pass)) {
                delete_option('pn_mailguard_imap_password');
            } elseif ($submitted_imap_pass !== '********') {
                update_option('pn_mailguard_imap_password', PN_Mailguard_Crypto::encrypt($submitted_imap_pass));
            }
        }

        // Save uninstall cleanup preference
        // HTML checkboxes send no value when unchecked — treat missing as '0'.
        update_option('pn_mailguard_uninstall_cleanup', empty($_POST['pn_mailguard_uninstall_cleanup']) ? '0' : '1');

        // Clear models cache when API key changes
        PN_Mailguard_AI::clear_models_cache();

        add_settings_error('pn_mailguard_messages', 'settings_saved', __('Settings saved.', 'pointnet-mailguard'), 'success');
    }

    /**
     * AJAX handler to save monitor settings (email, IP, alert email) from the Monitor tab inline edit.
     */
    public static function ajax_save_monitor(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        // Only save fields that were actually sent in the request.
        // This prevents overwriting the other monitor with an empty string.
        if (isset($_POST['pn_mailguard_check_email'])) {
            $check_email = sanitize_email(wp_unslash($_POST['pn_mailguard_check_email']));
            if (!empty($check_email) && !is_email($check_email)) {
                wp_send_json_error(['message' => __('Please enter a valid email address to monitor.', 'pointnet-mailguard')]);
            }
            update_option('pn_mailguard_check_email', $check_email);
        }

        if (isset($_POST['pn_mailguard_check_ip'])) {
            $check_ip = sanitize_text_field(wp_unslash($_POST['pn_mailguard_check_ip']));
            if (!empty($check_ip) && !filter_var($check_ip, FILTER_VALIDATE_IP)) {
                wp_send_json_error(['message' => __('Please enter a valid IPv4 or IPv6 address.', 'pointnet-mailguard')]);
            }
            update_option('pn_mailguard_check_ip', $check_ip);
        }

        if (isset($_POST['pn_mailguard_email_alert'])) {
            $alert_email = sanitize_email(wp_unslash($_POST['pn_mailguard_email_alert']));
            if (!empty($alert_email) && !is_email($alert_email)) {
                wp_send_json_error(['message' => __('Please enter a valid alert email address.', 'pointnet-mailguard')]);
            }
            if (!empty($alert_email)) {
                update_option('pn_mailguard_email_alert', $alert_email);
            }
        }

        wp_send_json_success(['message' => __('Monitor settings saved.', 'pointnet-mailguard')]);
    }

    // -------------------------------------------------------------------------
    // Menu
    // -------------------------------------------------------------------------

    public static function add_menu(): void {
        add_menu_page(
            'PointNet Mail Guard',
            'PointNet Mail Guard',
            'manage_options',
            'pn-mailguard',
            ['PN_Mailguard_Dashboard', 'render_page'],
            'dashicons-shield'
        );
    }

    public static function action_links(array $links): array {
        $url  = admin_url('admin.php?page=pn-mailguard');
        array_unshift($links, '<a href="' . esc_url($url) . '">' . __('Settings', 'pointnet-mailguard') . '</a>');
        return $links;
    }

    /**
     * Extract monitored domain from saved email, or empty string.
     */
    private static function get_monitored_domain(): string {
        $email = get_option('pn_mailguard_check_email', '');
        if (!empty($email) && is_email($email)) {
            return strtolower(explode('@', $email)[1]);
        }
        return '';
    }

    // -------------------------------------------------------------------------
    // Page router
    // -------------------------------------------------------------------------

    public static function render_page(): void {
        if (!current_user_can('manage_options')) wp_die(esc_html__('Unauthorized', 'pointnet-mailguard'));

        $tabs   = ['monitors', 'dmarcreports', 'customip', 'dnstools', 'advanced', 'support'];
        $raw    = isset($_GET['tab']) ? sanitize_text_field(wp_unslash($_GET['tab'])) : '';
        $tab    = in_array($raw, $tabs, true) ? $raw : 'monitors';
        $base   = admin_url('admin.php?page=pn-mailguard');

        $check_email = get_option('pn_mailguard_check_email', '');
        $check_ip    = get_option('pn_mailguard_check_ip', '');
        $alert_email = get_option('pn_mailguard_email_alert', get_option('admin_email'));
        $configured  = !empty($check_email) || !empty($check_ip);
        ?>
        <div class="wrap pn-page-wrap">
            <h1 style="display:flex; align-items:center; gap:10px;">
                🛡️ PointNet Mail Guard
                <small style="font-size:14px; font-weight:400; color:#999;">v<?php echo esc_html(PN_MAILGUARD_VERSION); ?></small>
            </h1>

            <?php settings_errors('pn_mailguard_messages'); ?>

            <nav class="nav-tab-wrapper" style="margin-bottom:20px;">
                <?php
                $tab_labels = [
                    'monitors'     => '📧 ' . __('Email & MX Monitor', 'pointnet-mailguard'),
                    'dmarcreports' => '📊 ' . __('DMARC Reports',      'pointnet-mailguard'),
                    'customip'     => '🌐 ' . __('Custom IP Monitor',   'pointnet-mailguard'),
                    'dnstools'     => '🔬 ' . __('DNS & IP Tools',      'pointnet-mailguard'),
                    'advanced'     => '⚙️ '  . __('Advanced',          'pointnet-mailguard'),
                    'support'      => '📤 '  . __('Export / Support',    'pointnet-mailguard'),
                ];
                foreach ($tab_labels as $key => $label) {
                    $active = $tab === $key ? 'nav-tab-active' : '';
                    echo '<a href="' . esc_url($base . '&tab=' . $key) . '" class="nav-tab ' . esc_attr($active) . '">' . esc_html($label) . '</a>';
                }
                ?>
            </nav>

            <?php
            switch ($tab) {
                case 'monitors':     self::render_monitors($check_email, $check_ip); break;
                case 'dmarcreports': self::render_dmarcreports(); break;
                case 'customip':     self::render_custom_ip($check_ip); break;
                case 'dnstools':     self::render_dnstools(); break;
                case 'advanced':     self::render_advanced(); break;
                case 'support':      self::render_support(); break;
            }

            self::render_doc_drawer();
            ?>
        </div>
        <?php
    }

    /**
     * Render the Off-Canvas Documentation Drawer container.
     */
    private static function render_doc_drawer(): void {
        ?>
        <div id="pn-doc-drawer-backdrop" class="pn-doc-drawer-backdrop"></div>
        <div id="pn-doc-drawer" class="pn-doc-drawer" role="dialog" aria-modal="true" aria-labelledby="pn-doc-drawer-title">
            <div class="pn-doc-drawer-header">
                <div class="pn-doc-drawer-title-wrap">
                    <span id="pn-doc-drawer-icon" class="pn-doc-drawer-icon">🔐</span>
                    <div>
                        <h3 id="pn-doc-drawer-title" class="pn-doc-drawer-title"><?php esc_html_e('Contextual Documentation', 'pointnet-mailguard'); ?></h3>
                        <span id="pn-doc-drawer-subtitle" class="pn-doc-drawer-subtitle"><?php esc_html_e('DNS & Email Security Guide', 'pointnet-mailguard'); ?></span>
                    </div>
                </div>
                <button type="button" id="pn-doc-drawer-close" class="pn-doc-drawer-close" aria-label="<?php esc_attr_e('Close', 'pointnet-mailguard'); ?>">&times;</button>
            </div>
            <div id="pn-doc-drawer-content" class="pn-doc-drawer-content">
                <!-- Populated dynamically by admin.js -->
            </div>
            <div class="pn-doc-drawer-footer">
                <a id="pn-doc-drawer-tool-link" href="<?php echo esc_url(admin_url('admin.php?page=pn-mailguard&tab=dnstools')); ?>" class="button button-primary">
                    🔍 <?php esc_html_e('Open Live Analysis Tool', 'pointnet-mailguard'); ?>
                </a>
                <button type="button" class="button button-secondary pn-doc-drawer-close-btn">
                    <?php esc_html_e('Close', 'pointnet-mailguard'); ?>
                </button>
            </div>
        </div>
        <?php
    }

    // -------------------------------------------------------------------------
    // Onboarding wizard
    // -------------------------------------------------------------------------

    /**
     * Render inline onboarding wizard for first-time configuration.
     */
    private static function render_onboarding(): void {
        $dkim_sel = get_option('pn_mailguard_dkim_selector', '');
        ?>
        <div style="background:linear-gradient(135deg,#f0f6ff 0%,#e8f0fb 100%); border:1px solid #c8d8f0; border-radius:10px; padding:24px; margin-bottom:24px;">
            <h2 style="font-size:18px; margin:0 0 4px; color:#1d2327;">
                🚀 <?php esc_html_e('Welcome to PointNet Mail Guard!', 'pointnet-mailguard'); ?>
            </h2>
            <p style="font-size:13px; color:#50575e; margin:0 0 16px; line-height:1.5;">
                <?php esc_html_e('Set up your monitoring in 2 minutes. We automatically analyze 7 security layers: SPF, DMARC, DKIM, MTA-STS, DNSSEC, DNSBL Blacklists, and Mail Server IP/PTR.', 'pointnet-mailguard'); ?>
            </p>

            <form method="post" style="display:flex; flex-wrap:wrap; gap:16px;">
                <?php wp_nonce_field('pn_mailguard_save_action', 'pn_mailguard_nonce'); ?>
                <div style="background:#fff; border-radius:8px; padding:16px; border:1px solid #dcdcde; flex:1 1 240px; min-width:240px;">
                    <div style="font-size:24px; margin-bottom:8px;">📧</div>
                    <p style="font-weight:600; margin:0 0 4px;"><?php esc_html_e('Step 1: Email to monitor', 'pointnet-mailguard'); ?></p>
                    <p style="font-size:12px; color:#666; margin:0 0 10px;">
                        <?php esc_html_e('The email address you send from — we will detect your mail server IP automatically via MX lookup.', 'pointnet-mailguard'); ?>
                    </p>
                    <input type="email" id="onboarding-email" name="pn_mailguard_check_email" value="" class="regular-text" placeholder="info@yourdomain.com" style="width:100%;">
                </div>

                <div style="background:#fff; border-radius:8px; padding:16px; border:1px solid #dcdcde; flex:1 1 240px; min-width:240px;">
                    <div style="font-size:24px; margin-bottom:8px;">🌐</div>
                    <p style="font-weight:600; margin:0 0 4px;">
                        <?php esc_html_e('Step 2: Additional IP to monitor', 'pointnet-mailguard'); ?>
                        <span style="font-size:11px; font-weight:400; color:#999; margin-left:4px;"><?php esc_html_e('(optional)', 'pointnet-mailguard'); ?></span>
                    </p>
                    <p style="font-size:12px; color:#666; margin:0 0 10px;">
                        <?php esc_html_e('Your mail server IP is already monitored via the email above. You only need this if you want to monitor a different server — for example your web server, a VPS, or an SMTP relay service.', 'pointnet-mailguard'); ?>
                    </p>
                    <input type="text" name="pn_mailguard_check_ip" value="" class="regular-text" placeholder="1.2.3.4" style="width:100%;">
                    <p style="font-size:11px; color:#999; margin:4px 0 0;"><em><?php esc_html_e('Leave empty to skip — the email monitor already covers your mail server.', 'pointnet-mailguard'); ?></em></p>
                </div>

                <div style="background:#fff; border-radius:8px; padding:16px; border:1px solid #dcdcde; flex:1 1 240px; min-width:240px;">
                    <div style="font-size:24px; margin-bottom:8px;">📬</div>
                    <p style="font-weight:600; margin:0 0 4px;"><?php esc_html_e('Step 3: Alert email', 'pointnet-mailguard'); ?></p>
                    <p style="font-size:12px; color:#666; margin:0 0 10px;">
                        <?php esc_html_e('Where to receive alerts when problems are detected.', 'pointnet-mailguard'); ?>
                    </p>
                    <input type="email" name="pn_mailguard_email_alert" id="onboarding-alert-email" value="<?php echo esc_attr(get_option('admin_email')); ?>" class="regular-text" style="width:100%;">
                    <p style="font-size:11px; color:#dba617; margin:6px 0 6px; background:#fff8e5; padding:6px 8px; border-radius:3px;">
                        💡 <?php esc_html_e('Tip: use a different email from the one you monitor. If your mail server has issues, alerts sent to the same monitored address may not arrive.', 'pointnet-mailguard'); ?>
                    </p>
                    <label for="onboarding-alert-level" style="font-size:11px; font-weight:600; display:block; margin-bottom:4px;">📊 <?php esc_html_e('Notification level', 'pointnet-mailguard'); ?></label>
                    <select name="pn_mailguard_alert_level" id="onboarding-alert-level" style="width:100%; padding:6px 8px; font-size:12px;">
                        <option value="all" selected><?php esc_html_e('All issues (warnings + errors)', 'pointnet-mailguard'); ?></option>
                        <option value="errors"><?php esc_html_e('Errors only (DNSBL, DKIM errors, scan failures)', 'pointnet-mailguard'); ?></option>
                        <option value="none"><?php esc_html_e('None (disable email notifications)', 'pointnet-mailguard'); ?></option>
                    </select>
                </div>

                <div style="background:#fff; border-radius:8px; padding:16px; border:1px solid #dcdcde; flex:1 1 240px; min-width:240px;">
                    <div style="font-size:24px; margin-bottom:8px;">🔑</div>
                    <p style="font-weight:600; margin:0 0 4px;"><?php esc_html_e('Step 4: DKIM Selector (optional)', 'pointnet-mailguard'); ?></p>
                    <p style="font-size:12px; color:#666; margin:0 0 10px;">
                        <?php esc_html_e('If known, enter your DKIM selector. Leave empty to auto-detect.', 'pointnet-mailguard'); ?>
                    </p>
                    <div style="display:flex; flex-wrap:wrap; gap:6px;">
                        <input type="text" name="pn_mailguard_dkim_selector" id="onboarding-dkim-selector"
                            value="<?php echo esc_attr($dkim_sel); ?>"
                            placeholder="<?php esc_attr_e('Leave empty to auto-detect', 'pointnet-mailguard'); ?>"
                            style="flex:1; padding:6px 8px; font-size:13px;">
                        <button type="button" id="onboarding-dkim-detect" class="button button-secondary">
                            🔍 <?php esc_html_e('Detect', 'pointnet-mailguard'); ?>
                        </button>
                    </div>
                    <div id="onboarding-dkim-status" style="font-size:11px; margin-top:6px;"></div>
                </div>

                <!-- Step 5: IMAP Auto-Fetch (Optional) -->
                <?php $imap_cfg = PN_Mailguard_Imap_Fetcher::get_config(); ?>
                <div style="background:#fff; border-radius:8px; padding:16px; border:1px solid #dcdcde; flex:1 1 100%; min-width:280px;">
                    <div style="font-size:24px; margin-bottom:8px;">📬</div>
                    <p style="font-weight:600; margin:0 0 4px;">
                        <?php esc_html_e('Step 5: DMARC & TLSRPT Report Auto-Fetch (IMAP)', 'pointnet-mailguard'); ?>
                        <span style="font-size:11px; font-weight:400; color:#999; margin-left:4px;"><?php esc_html_e('(optional)', 'pointnet-mailguard'); ?></span>
                    </p>
                    <p style="font-size:12px; color:#666; margin:0 0 12px;">
                        <?php esc_html_e('Connect a dedicated mailbox (e.g. dmarc@yourdomain.com) to automatically download and process report attachments.', 'pointnet-mailguard'); ?>
                    </p>

                    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:10px; margin-bottom:10px;">
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:3px;"><?php esc_html_e('IMAP Host', 'pointnet-mailguard'); ?></label>
                            <input type="text" id="onboarding-imap-host" name="pn_mailguard_imap_host" value="<?php echo esc_attr($imap_cfg['host']); ?>" placeholder="mail.yourdomain.com" style="width:100%; font-size:12px;">
                        </div>
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:3px;"><?php esc_html_e('Port', 'pointnet-mailguard'); ?></label>
                            <input type="number" id="onboarding-imap-port" name="pn_mailguard_imap_port" value="<?php echo esc_attr($imap_cfg['port']); ?>" placeholder="993" style="width:100%; font-size:12px;">
                        </div>
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:3px;"><?php esc_html_e('Encryption', 'pointnet-mailguard'); ?></label>
                            <select id="onboarding-imap-encryption" name="pn_mailguard_imap_encryption" style="width:100%; font-size:12px;">
                                <option value="ssl" <?php selected($imap_cfg['encryption'], 'ssl'); ?>>SSL / TLS (993)</option>
                                <option value="tls" <?php selected($imap_cfg['encryption'], 'tls'); ?>>STARTTLS (143)</option>
                                <option value="none" <?php selected($imap_cfg['encryption'], 'none'); ?>>None</option>
                            </select>
                        </div>
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:3px;"><?php esc_html_e('Username', 'pointnet-mailguard'); ?></label>
                            <input type="text" id="onboarding-imap-username" name="pn_mailguard_imap_username" value="<?php echo esc_attr($imap_cfg['username']); ?>" placeholder="dmarc@yourdomain.com" style="width:100%; font-size:12px;">
                        </div>
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:3px;"><?php esc_html_e('Password', 'pointnet-mailguard'); ?></label>
                            <input type="password" id="onboarding-imap-password" name="pn_mailguard_imap_password" value="<?php echo !empty($imap_cfg['password']) ? '********' : ''; ?>" placeholder="••••••••" style="width:100%; font-size:12px;">
                        </div>
                    </div>

                    <div style="display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:16px; margin-top:10px;">
                        <div style="display:flex; flex-wrap:wrap; align-items:center; gap:16px;">
                            <label style="font-size:12px; font-weight:600; display:inline-flex; align-items:center; gap:6px; cursor:pointer;">
                                <input type="checkbox" name="pn_mailguard_imap_auto_fetch" value="1" <?php checked($imap_cfg['auto_fetch']); ?>>
                                <?php esc_html_e('Enable automatic hourly polling (WP-Cron)', 'pointnet-mailguard'); ?>
                            </label>
                            <label style="font-size:12px; color:#555; display:inline-flex; align-items:center; gap:6px;">
                                <span><?php esc_html_e('Action after import:', 'pointnet-mailguard'); ?></span>
                                <select name="pn_mailguard_imap_action_after" style="font-size:12px;">
                                    <option value="delete" <?php selected($imap_cfg['action_after'], 'delete'); ?>><?php esc_html_e('Delete email (Recommended)', 'pointnet-mailguard'); ?></option>
                                    <option value="mark_read" <?php selected($imap_cfg['action_after'], 'mark_read'); ?>><?php esc_html_e('Mark as read', 'pointnet-mailguard'); ?></option>
                                </select>
                            </label>
                        </div>
                        <button type="button" id="onboarding-imap-test-btn" class="button button-secondary" style="font-size:12px;">
                            🧪 <?php esc_html_e('Test IMAP Connection', 'pointnet-mailguard'); ?>
                        </button>
                    </div>
                    <div id="onboarding-imap-status" style="display:none; font-size:12px; margin-top:10px;"></div>
                </div>

                <!-- Step 6: Google Gemini AI Advisor (Optional) -->
                <?php
                $saved_gemini_key = get_option('pn_mailguard_gemini_key', '');
                ?>
                <div style="background:#fff; border-radius:8px; padding:16px; border:1px solid #dcdcde; flex:1 1 100%; min-width:280px;">
                    <div style="font-size:24px; margin-bottom:8px;">🤖</div>
                    <p style="font-weight:600; margin:0 0 4px;">
                        <?php esc_html_e('Step 6: Google Gemini AI Deliverability Advisor', 'pointnet-mailguard'); ?>
                        <span style="font-size:11px; font-weight:400; color:#999; margin-left:4px;"><?php esc_html_e('(optional)', 'pointnet-mailguard'); ?></span>
                    </p>
                    <p style="font-size:12px; color:#666; margin:0 0 10px;">
                        <?php esc_html_e('Get AI-powered email deliverability recommendations, root cause diagnosis, and interactive chat assistance.', 'pointnet-mailguard'); ?>
                    </p>
                    <div style="display:flex; flex-wrap:wrap; gap:10px; align-items:center;">
                        <input type="password" name="pn_mailguard_gemini_key" value="<?php echo !empty($saved_gemini_key) ? '********' : ''; ?>" placeholder="<?php esc_attr_e('Enter your Gemini API key (AIzaSy...)', 'pointnet-mailguard'); ?>" style="flex:1; min-width:260px; font-size:12px;">
                        <span style="font-size:11px; color:#666;">
                            <?php
                            echo sprintf(
                                /* translators: %s: URL to Google AI Studio */
                                esc_html__('Get a free API key at %s', 'pointnet-mailguard'),
                                '<a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener noreferrer" style="color:#2271b1;">Google AI Studio ↗</a>'
                            );
                            ?>
                        </span>
                    </div>
                </div>

                <div style="flex:1 1 100%;">
                    <input type="submit" name="pn_mailguard_save_settings" class="button button-primary button-hero" value="<?php esc_attr_e('Save & Start Monitoring →', 'pointnet-mailguard'); ?>" style="width:100%;">
                </div>
            </form>
        </div>
        <?php
    }

    // -------------------------------------------------------------------------
    // TAB: Monitors (full DNS details + AI)
    // -------------------------------------------------------------------------

    private static function render_monitors(string $check_email, string $check_ip): void {
        $configured = !empty($check_email) || !empty($check_ip);
        $next       = wp_next_scheduled('pn_mailguard_daily_scan');
        $domain     = self::get_monitored_domain();

        if (!$configured) {
            self::render_onboarding();
            return;
        }

        $last_email = self::get_last_log('email');
        $last_ip    = self::get_last_log('ip');

        // Read cached DNS analysis from transient (populated by last manual or cron scan).
        // This gives us complete check tables without live DNS lookups on every admin page load.
        $dns_cache = $domain ? get_transient('pn_mailguard_dns_cache_' . $domain) : null;
        $spf_data    = null;
        $dmarc_data  = null;
        $dkim_data   = null;
        $mtasts_data = null;
        $dnssec_data = null;
        if ($dns_cache) {
            $spf_data    = $dns_cache['spf'] ?? null;
            $dmarc_data  = $dns_cache['dmarc'] ?? null;
            $dkim_data   = $dns_cache['dkim'] ?? null;
            $mtasts_data = $dns_cache['mtasts'] ?? null;
            $dnssec_data = $dns_cache['dnssec'] ?? null;
        }

        // Fallback: build lightweight status objects from last email log when no cache exists.
        if (!$spf_data || !$dmarc_data || !$dkim_data || !$mtasts_data || !$dnssec_data) {
            $parse_status = function(string $details, string $label): ?array {
                if (empty($details)) return null;
                if (preg_match('/' . preg_quote($label, '/') . ':\s*(OK|WARNING|ERROR|MISSING)/i', $details, $m)) {
                    $raw = strtoupper($m[1]);
                    $status = match ($raw) {
                        'OK'      => 'ok',
                        'WARNING' => 'warning',
                        'ERROR'   => 'error',
                        'MISSING' => 'missing',
                        default   => 'warning',
                    };
                    return ['status' => $status];
                }
                return null;
            };
            $last_details = $last_email->details ?? '';
            if ((!$spf_data || empty($spf_data['checks'])) && $domain)       $spf_data    = PN_Mailguard_SPF::analyze($domain);
            if ((!$dmarc_data || empty($dmarc_data['checks'])) && $domain)   $dmarc_data  = PN_Mailguard_DMARC::analyze($domain);
            if ((!$mtasts_data || empty($mtasts_data['checks'])) && $domain) $mtasts_data = PN_Mailguard_MTA_STS::analyze($domain);
            if ((!$dnssec_data || empty($dnssec_data['checks'])) && $domain) $dnssec_data = PN_Mailguard_Dnssec::analyze($domain);

            if ((!$dkim_data || empty($dkim_data['checks'])) && $domain) {
                $sel = get_option('pn_mailguard_dkim_selector', '');
                if (empty($sel) && !PN_Mailguard_DKIM::is_public_provider($domain)) {
                    $d = PN_Mailguard_DKIM::autodetect($domain);
                    if (!empty($d['selector'])) {
                        $sel = $d['selector'];
                        update_option('pn_mailguard_dkim_selector', $sel);
                    }
                }
                if (!empty($sel)) {
                    $dkim_data = PN_Mailguard_DKIM::analyze($domain, $sel);
                } elseif (!$dkim_data) {
                    $dkim_data = $parse_status($last_details, 'DKIM') ?? ['status' => 'missing'];
                }
            }
        }

        // Extract DNSBL results from last email log
        $dnsbl_results = null;
        if ($last_email && !empty($last_email->details)) {
            $details = $last_email->details;
            $dnsbl_results = [];
            // Parse pipe-separated details looking for blacklist names
            $parts = explode(' | ', $details);
            foreach ($parts as $part) {
                $part = trim($part);
                // Lines like "SpamCop: CLEAN" or "Barracuda: LISTED"
                if (preg_match('/^([A-Za-z0-9\s]+?):\s*(CLEAN|LISTED)$/', $part, $m)) {
                    $dnsbl_results[trim($m[1])] = $m[2];
                }
            }
        }

        $issues = 0;
        if ($spf_data    && $spf_data['status']   !== 'ok') $issues++;
        if ($dmarc_data   && $dmarc_data['status']  !== 'ok') $issues++;
        if ($dkim_data    && $dkim_data['status']   !== 'ok') $issues++;
        if ($dnssec_data  && $dnssec_data['status'] !== 'ok') $issues++;
        $email_active = !empty($check_email) && is_email($check_email);
        $ip_active    = !empty($check_ip) && filter_var($check_ip, FILTER_VALIDATE_IP);
        if ($email_active && $last_email && in_array($last_email->status, ['ALERT', 'ALERT + PTR', 'ERROR'], true)) $issues++;
        if ($ip_active && $last_ip && in_array($last_ip->status, ['ALERT', 'ALERT + PTR', 'ERROR'], true)) $issues++;

        if ($issues === 0) {
            $light = '#00a32a'; $light_bg = '#edfaef'; $light_label = __('All good', 'pointnet-mailguard');
        } elseif ($issues <= 2) {
            $light = '#dba617'; $light_bg = '#fff8e5'; $light_label = __('Attention needed', 'pointnet-mailguard');
        } else {
            $light = '#d63638'; $light_bg = '#fbeaea'; $light_label = __('Issues detected', 'pointnet-mailguard');
        }
        ?>

        <?php
        if (!$next || $next <= time()) {
            if ($next && $next <= time()) {
                wp_unschedule_event($next, 'pn_mailguard_daily_scan');
            }
            if (!wp_next_scheduled('pn_mailguard_daily_scan')) {
                wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'pn_mailguard_daily_scan');
            }
            $next = wp_next_scheduled('pn_mailguard_daily_scan');
        }
        ?>
        <?php if ($next): ?>
        <div class="notice notice-info inline" style="margin-bottom:20px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
            <p style="margin:0;">🕒 <?php esc_html_e('Next automatic scan:', 'pointnet-mailguard'); ?>
            <strong><?php echo esc_html(get_date_from_gmt(gmdate('Y-m-d H:i:s', $next), 'D d M Y \a\t H:i')); ?></strong></p>
            <button type="button" id="pn-run-scheduled-btn" class="button button-secondary" style="white-space:nowrap;">
                ▶️ <?php esc_html_e('Run Scheduled Scan Now', 'pointnet-mailguard'); ?>
            </button>
        </div>
        <?php endif; ?>

        <!-- Global status indicator -->
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:20px; margin-bottom:20px; display:flex; align-items:center; gap:20px; flex-wrap:wrap;">
            <div class="pn-status-indicator" style="background:<?php echo esc_attr($light_bg); ?>; border:3px solid <?php echo esc_attr($light); ?>;">
                <span style="font-size:28px;">
                    <?php echo $issues === 0 ? '✅' : ($issues <= 2 ? '⚠️' : '🔴'); ?>
                </span>
            </div>
            <div style="flex:1;">
                <p style="font-size:16px; font-weight:600; margin:0 0 6px; color:<?php echo esc_attr($light); ?>;">
                    <?php echo esc_html($light_label); ?>
                </p>
                <div style="display:flex; gap:8px; flex-wrap:wrap;">
                    <?php self::badge('SPF',     $spf_data,    'spf'); ?>
                    <?php self::badge('DMARC',   $dmarc_data,  'dmarc'); ?>
                    <?php self::badge('DKIM',    $dkim_data,   'dkim'); ?>
                    <?php self::badge('MTA-STS', $mtasts_data, 'mtasts'); ?>
                    <?php self::badge('DNSSEC',  $dnssec_data, 'dnssec'); ?>
                    <?php
                    // DNSBL badge: shows blacklist status of the mail server IP
                    $dnsbl_has_listed = false;
                    $dnsbl_has_data   = false;
                    if (!empty($dnsbl_results)) {
                        $dnsbl_has_data = true;
                        foreach ($dnsbl_results as $_st) {
                            if ($_st === 'LISTED') {
                                $dnsbl_has_listed = true;
                                break;
                            }
                        }
                    }
                    if ($dnsbl_has_listed):
                        echo '<span class="pn-doc-badge" data-docs="dnsbl" style="background:#fbeaea;color:#a30000;font-size:11px;font-weight:600;padding:3px 10px;border-radius:4px;white-space:nowrap;cursor:pointer;" title="' . esc_attr__('Click for contextual guide', 'pointnet-mailguard') . '">✗ DNSBL ℹ️</span>';
                    elseif ($dnsbl_has_data):
                        echo '<span class="pn-doc-badge" data-docs="dnsbl" style="background:#edfaef;color:#00a32a;font-size:11px;font-weight:600;padding:3px 10px;border-radius:4px;white-space:nowrap;cursor:pointer;" title="' . esc_attr__('Click for contextual guide', 'pointnet-mailguard') . '">✓ DNSBL ℹ️</span>';
                    else:
                        echo '<span class="pn-doc-badge" data-docs="dnsbl" style="background:#f0f0f0;color:#999;font-size:11px;font-weight:600;padding:3px 10px;border-radius:4px;white-space:nowrap;cursor:pointer;" title="' . esc_attr__('Click for contextual guide', 'pointnet-mailguard') . '">DNSBL — ℹ️</span>';
                    endif;
                    ?>
                    <?php
                    // Show MX-resolved IP from last email log instead of Custom IP Monitor
                    $mx_ip_label = '';
                    $mx_ip_alert = false;
                    $mx_ip_warn  = false;
                    if ($last_email && !empty($last_email->details)) {
                        preg_match('/MX:\s*[^\s]+\s*\(([^)]+)\)/', $last_email->details, $mx_match);
                        if (!empty($mx_match[1])) {
                            $mx_ip_label = $mx_match[1];
                            $mx_ip_alert = in_array($last_email->status, ['ALERT', 'ALERT + PTR', 'ERROR'], true);
                            $mx_ip_warn  = in_array($last_email->status, ['PTR WARNING', 'SPF WARNING'], true);
                        }
                    }
                    if (!empty($mx_ip_label)):
                        if ($mx_ip_alert): $bg = '#fbeaea'; $txt = '#a30000'; $icon = '✗';
                        elseif ($mx_ip_warn): $bg = '#fff8e5'; $txt = '#996800'; $icon = '⚠';
                        else: $bg = '#edfaef'; $txt = '#00a32a'; $icon = '✓';
                        endif;
                        echo '<span class="pn-doc-badge" data-docs="ip" style="background:' . esc_attr($bg) . ';color:' . esc_attr($txt) . ';font-size:11px;font-weight:600;padding:3px 10px;border-radius:4px;white-space:nowrap;cursor:pointer;" title="' . esc_attr__('Click for contextual guide', 'pointnet-mailguard') . '">' . esc_html($icon) . ' IP ' . esc_html($mx_ip_label) . ' ℹ️</span>';
                    else:
                        echo '<span class="pn-doc-badge" data-docs="ip" style="background:#f0f0f0;color:#999;font-size:11px;font-weight:600;padding:3px 10px;border-radius:4px;cursor:pointer;" title="' . esc_attr__('Click for contextual guide', 'pointnet-mailguard') . '">IP — ℹ️</span>';
                    endif;
                    ?>
                </div>
            </div>
        </div>

        <!-- Email Monitor card (full width, standalone) -->
        <div style="margin-bottom:24px;">
            <?php self::monitor_card_v2('email', $check_email, $last_email, $domain); ?>
        </div>

        <!-- DNS Record Status -->
        <?php if ($domain):
            $last_scan_date = $last_email->scan_date ?? '';
        ?>
        <h2 style="font-size:15px; margin:0 0 12px; color:#50575e;">🔐 <?php esc_html_e('DNS Record Status', 'pointnet-mailguard'); ?></h2>
        <div class="pn-dns-status-grid" style="margin-bottom:24px;">
            <?php self::render_analyzer_section('spf',    '🔐', 'SPF',     $spf_data,    $domain, $last_scan_date); ?>
            <?php self::render_analyzer_section('dmarc',  '📋', 'DMARC',   $dmarc_data,  $domain, $last_scan_date); ?>
            <?php self::render_analyzer_section('dkim',   '🔑', 'DKIM',    $dkim_data,   $domain, $last_scan_date); ?>
            <?php self::render_analyzer_section('mtasts', '🛡️', 'MTA-STS', $mtasts_data, $domain, $last_scan_date); ?>
            <?php self::render_analyzer_section('dnssec', '🔒', 'DNSSEC',  $dnssec_data, $domain, $last_scan_date); ?>
        </div>
        <?php endif; ?>

        <!-- DNSBL check results -->
        <?php if (!empty($dnsbl_results)):
            $dnsbl_ip = '';
            if ($last_email && !empty($last_email->details)) {
                preg_match('/MX:\s*[^\s]+\s*\(([^)]+)\)/', $last_email->details, $mx_match);
                if (!empty($mx_match[1])) {
                    $dnsbl_ip = $mx_match[1];
                }
            }
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px; margin-bottom:24px;">
            <h2 style="font-size:15px; margin:0 0 12px; color:#50575e;">🚫 <?php esc_html_e('DNSBL Blacklist Check', 'pointnet-mailguard'); ?>
                <?php if (!empty($dnsbl_ip)): ?>
                <span style="font-size:12px; color:#666; font-weight:400;"> — <?php echo esc_html($dnsbl_ip); ?></span>
                <?php endif; ?>
                <?php if (!empty($last_scan_date)): ?>
                <span style="font-size:11px; color:#999; font-weight:400;"> — <?php echo esc_html($last_scan_date); ?></span>
                <?php endif; ?>
            </h2>
            <div style="display:flex; flex-wrap:wrap; gap:8px;">
                <?php foreach ($dnsbl_results as $dnsbl_name => $dnsbl_status): ?>
                    <?php
                    $is_clean = ($dnsbl_status === 'CLEAN');
                    $bg   = $is_clean ? '#edfaef' : '#fbeaea';
                    $text = $is_clean ? '#00a32a' : '#a30000';
                    ?>
                    <span style="background:<?php echo esc_attr($bg); ?>; color:<?php echo esc_attr($text); ?>; font-size:11px; font-weight:600; padding:4px 10px; border-radius:4px; white-space:nowrap;">
                        <?php echo $is_clean ? '✓' : '✗'; ?>
                        <?php echo esc_html($dnsbl_name); ?>
                    </span>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- Recent scans compact (email only) -->
        <h2 style="font-size:15px; margin:0 0 12px; color:#50575e;">📋 <?php esc_html_e('Recent scans', 'pointnet-mailguard'); ?></h2>
        <div style="margin-bottom:24px;">
            <?php self::monitor_card('email', __('Email Monitor', 'pointnet-mailguard'), '📧', $check_email); ?>
        </div>

        <?php
    }

    private static function badge(string $label, $data, string $type = ''): void {
        if (!$data) {
            echo '<span class="pn-doc-badge" data-docs="' . esc_attr($type) . '" style="background:#f0f0f0; color:#999; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px; cursor:pointer;" title="' . esc_attr__('Click for contextual guide', 'pointnet-mailguard') . '">' . esc_html($label) . ' — ℹ️</span>';
            return;
        }
        $status_class = match ($data['status']) {
            'ok'               => 'passed',
            'error', 'missing' => 'error',
            default            => 'warning',
        };
        if ($status_class === 'passed') {
            echo '<span class="pn-doc-badge" data-docs="' . esc_attr($type) . '" style="background:#edfaef; color:#00a32a; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px; cursor:pointer;" title="' . esc_attr__('Click for contextual guide', 'pointnet-mailguard') . '">✓ ' . esc_html($label) . ' ℹ️</span>';
        } elseif ($status_class === 'error') {
            echo '<span class="pn-doc-badge" data-docs="' . esc_attr($type) . '" style="background:#fbeaea; color:#a30000; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px; cursor:pointer;" title="' . esc_attr__('Click for contextual guide', 'pointnet-mailguard') . '">✗ ' . esc_html($label) . ' ℹ️</span>';
        } else {
            echo '<span class="pn-doc-badge" data-docs="' . esc_attr($type) . '" style="background:#fff8e5; color:#996800; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px; cursor:pointer;" title="' . esc_attr__('Click for contextual guide', 'pointnet-mailguard') . '">⚠ ' . esc_html($label) . ' ℹ️</span>';
        }
    }

    /**
     * Render the Custom IP Monitor tab (separate from Email Monitor).
     */
    private static function render_custom_ip(string $check_ip): void {
        $last_ip = self::get_last_log('ip');
        ?>
        <div style="margin-bottom:24px;">
            <?php if (!empty($check_ip) && filter_var($check_ip, FILTER_VALIDATE_IP)): ?>
                <?php self::monitor_card_v2('ip', $check_ip, $last_ip, null); ?>
            <?php else: ?>
            <div style="background:#fff; border:1px dashed #c0c0c0; border-radius:8px; padding:16px; text-align:center;">
                <span style="font-size:24px;">🌐</span>
                <p style="font-size:14px; font-weight:600; margin:8px 0 4px; color:#666;">
                    <?php esc_html_e('Custom IP Monitor not configured', 'pointnet-mailguard'); ?>
                </p>
                <p style="font-size:12px; color:#999; margin:0 0 12px;">
                    <?php esc_html_e('Monitor a separate IP (e.g. your VPS, SMTP relay or web server). This is independent from your email monitor.', 'pointnet-mailguard'); ?>
                </p>
                <button type="button" id="pn-dash-ip-edit" class="button button-secondary">
                    ➕ <?php esc_html_e('Add IP to Monitor', 'pointnet-mailguard'); ?>
                </button>
                <div id="pn-dash-ip-edit-form" style="display:none; margin-top:12px; text-align:left; background:#f8f8f8; border:1px solid #e0e0e0; border-radius:6px; padding:12px; max-width:400px; margin-left:auto; margin-right:auto;">
                    <p style="font-size:12px; font-weight:600; margin:0 0 8px; color:#333;">
                        <?php esc_html_e('Configure IP monitor:', 'pointnet-mailguard'); ?>
                    </p>
                    <label style="font-size:11px; font-weight:600; display:block; margin-bottom:2px;">🌐 <?php esc_html_e('IP Address', 'pointnet-mailguard'); ?></label>
                    <input type="text" class="pn-edit-ip" value="" placeholder="1.2.3.4" style="width:100%; padding:6px 8px; font-size:12px; margin-bottom:8px;">
                    <div style="display:flex; gap:6px;">
                        <button type="button" class="button button-primary button-small pn-edit-save" data-type="ip">
                            <?php esc_html_e('Save', 'pointnet-mailguard'); ?>
                        </button>
                        <button type="button" class="button button-secondary button-small pn-edit-cancel">
                            <?php esc_html_e('Cancel', 'pointnet-mailguard'); ?>
                        </button>
                        <span class="pn-edit-spinner" style="display:none; font-size:11px; color:#999; align-self:center;">⏳ <?php esc_html_e('Saving...', 'pointnet-mailguard'); ?></span>
                    </div>
                    <div class="pn-edit-msg" style="display:none; margin-top:6px; font-size:11px;"></div>
                </div>
            </div>
            <?php endif; ?>
        </div>

        <h2 style="font-size:15px; margin:0 0 12px; color:#50575e;">📋 <?php esc_html_e('Recent scans', 'pointnet-mailguard'); ?></h2>
        <div style="margin-bottom:24px;">
            <?php self::monitor_card('ip', __('Custom IP Monitor', 'pointnet-mailguard'), '🌐', $check_ip); ?>
        </div>
        <?php
    }

    private static function monitor_badge(string $label, $log, bool $active): void {
        if (!$active || !$log) {
            echo '<span style="background:#f0f0f0; color:#999; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px;">' . esc_html($label) . ' —</span>';
            return;
        }
        $alert = in_array($log->status, ['ALERT', 'ALERT + PTR', 'ERROR'], true);
        $warn  = in_array($log->status, ['PTR WARNING', 'SPF WARNING'], true);
        if ($alert) {
            echo '<span style="background:#fbeaea; color:#a30000; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px;">✗ ' . esc_html($label) . '</span>';
        } elseif ($warn) {
            echo '<span style="background:#fff8e5; color:#996800; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px;">⚠ ' . esc_html($label) . '</span>';
        } else {
            echo '<span style="background:#edfaef; color:#00a32a; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px;">✓ ' . esc_html($label) . '</span>';
        }
    }

    private static function monitor_card(string $type, string $label, string $icon, string $monitored_value = ''): void {
        global $wpdb;
        $keep = PN_Mailguard_Logger::get_keep_rows();
        $table = $wpdb->prefix . ($type === 'ip' ? PN_Mailguard_Installer::TABLE_IP : PN_Mailguard_Installer::TABLE_EMAIL);
        $logs  = $wpdb->get_results($wpdb->prepare("SELECT * FROM %i ORDER BY scan_date DESC LIMIT %d", $table, $keep));
        $is_email = ($type === 'email');
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px;">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">
                <span style="font-size:14px; font-weight:600;"><?php echo esc_html($icon . ' ' . $label); ?></span>
                <span style="font-size:11px; color:#999;">
                    <?php
                    /* translators: %d: number of recent scans shown */
                    echo esc_html(sprintf(__('Last %d scans', 'pointnet-mailguard'), $keep));
                    ?>
                </span>
            </div>
            <?php if (!empty($monitored_value)): ?>
            <div style="font-size:11px; color:#50575e; margin-bottom:10px; padding:4px 8px; background:#f0f6ff; border-radius:3px; display:inline-block;">
                <?php if ($is_email): ?>
                    📧 <?php echo esc_html($monitored_value); ?>
                <?php else: ?>
                    🌐 <?php echo esc_html($monitored_value); ?>
                <?php endif; ?>
            </div>
            <?php endif; ?>
            <?php if ($logs): ?>
                <?php foreach ($logs as $log):
                    $overall_color = PN_Mailguard_Logger::status_color($log->status);
                    // Parse details into individual check badges
                    $badges_html = '';
                    if (!empty($log->details)) {
                        $details_parts = explode(' | ', $log->details);
                        $dnsbl_badges = [];
                        foreach ($details_parts as $part) {
                            $part = trim($part);
                            // SPF: "SPF: OK (record)" or "SPF: WARNING" or "SPF: ERROR"
                            if (preg_match('/^SPF:\s*(OK|WARNING|ERROR)/i', $part, $m)) {
                                $s = strtoupper($m[1]);
                                if ($s === 'OK') { $bg = '#edfaef'; $txt = '#00a32a'; $label = 'SPF'; }
                                elseif ($s === 'WARNING') { $bg = '#fff8e5'; $txt = '#996800'; $label = 'SPF'; }
                                else { $bg = '#fbeaea'; $txt = '#a30000'; $label = 'SPF'; }
                                $badges_html .= '<span style="background:' . $bg . ';color:' . $txt . ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;white-space:nowrap;">' . esc_html($label) . '</span> ';
                            }
                            // DMARC
                            elseif (preg_match('/^DMARC:\s*(OK|WARNING|ERROR)/i', $part, $m)) {
                                $s = strtoupper($m[1]);
                                if ($s === 'OK') { $bg = '#edfaef'; $txt = '#00a32a'; }
                                elseif ($s === 'WARNING') { $bg = '#fff8e5'; $txt = '#996800'; }
                                else { $bg = '#fbeaea'; $txt = '#a30000'; }
                                $badges_html .= '<span style="background:' . $bg . ';color:' . $txt . ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;white-space:nowrap;">DMARC</span> ';
                            }
                            // DKIM
                            elseif (preg_match('/^DKIM:\s*(OK|WARNING|ERROR|MISSING)/i', $part, $m)) {
                                $s = strtoupper($m[1]);
                                if ($s === 'OK') { $bg = '#edfaef'; $txt = '#00a32a'; }
                                elseif ($s === 'WARNING') { $bg = '#fff8e5'; $txt = '#996800'; }
                                else { $bg = '#fbeaea'; $txt = '#a30000'; }
                                $badges_html .= '<span style="background:' . $bg . ';color:' . $txt . ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;white-space:nowrap;">DKIM</span> ';
                            }
                            // MTA-STS
                            elseif (preg_match('/^MTA-STS:\s*(OK|WARNING|ERROR|MISSING)/i', $part, $m)) {
                                $s = strtoupper($m[1]);
                                if ($s === 'OK') { $bg = '#edfaef'; $txt = '#00a32a'; }
                                elseif ($s === 'WARNING') { $bg = '#fff8e5'; $txt = '#996800'; }
                                else { $bg = '#fbeaea'; $txt = '#a30000'; }
                                $badges_html .= '<span style="background:' . $bg . ';color:' . $txt . ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;white-space:nowrap;">MTA-STS</span> ';
                            }
                            // Server
                            elseif (preg_match('/^Server:\s*(SHARED|SEPARATE)/i', $part, $m)) {
                                $s = strtoupper($m[1]);
                                if ($s === 'SEPARATE') { $bg = '#edfaef'; $txt = '#00a32a'; }
                                else { $bg = '#fff8e5'; $txt = '#996800'; }
                                $badges_html .= '<span style="background:' . $bg . ';color:' . $txt . ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;white-space:nowrap;">' . ($is_email ? 'SERVER' : '') . '</span> ';
                            }
                            // PTR: can be "PTR: host.eu" or "PTR: WARNING"
                            elseif (str_starts_with($part, 'PTR:')) {
                                $ptr_val = trim(substr($part, 4));
                                if (str_contains($ptr_val, 'WARNING') || empty($ptr_val)) {
                                    $bg = '#fff8e5'; $txt = '#996800'; $label = 'PTR';
                                } else {
                                    $bg = '#edfaef'; $txt = '#00a32a'; $label = 'PTR';
                                }
                                $badges_html .= '<span style="background:' . $bg . ';color:' . $txt . ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;white-space:nowrap;">PTR</span> ';
                            }
                            // DNSBL results like "SpamCop: CLEAN" or "Barracuda: LISTED" — collect them
                            elseif (preg_match('/^[A-Za-z0-9\s]+:\s*(CLEAN|LISTED)$/', $part, $m)) {
                                $s = $m[1];
                                // Use the DNSBL name as key
                                $dnsbl_name = trim(substr($part, 0, strpos($part, ':')));
                                if (!isset($dnsbl_badges['has_listed'])) {
                                    $dnsbl_badges['has_listed'] = false;
                                }
                                if ($s === 'LISTED') {
                                    $dnsbl_badges['has_listed'] = true;
                                }
                            }
                        }
                        // Add DNSBL overall badge
                        $has_listed = $dnsbl_badges['has_listed'] ?? false;
                        if ($has_listed) {
                            $badges_html .= '<span style="background:#fbeaea;color:#a30000;font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;white-space:nowrap;">DNSBL ✗</span> ';
                        } else {
                            $badges_html .= '<span style="background:#edfaef;color:#00a32a;font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;white-space:nowrap;">DNSBL</span> ';
                        }
                    }
                    ?>
                    <div style="padding:6px 0; border-bottom:0.5px solid #f0f0f0;">
                        <div style="display:flex; align-items:center; gap:6px; margin-bottom:2px;">
                            <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:<?php echo esc_attr($overall_color); ?>; flex-shrink:0;"></span>
                        <span style="font-size:11px; color:#666;"><?php echo esc_html($log->scan_date); ?></span>
                        <?php if (!$is_email && !empty($log->ip_address)): ?>
                        <span style="font-size:10px; color:#a6e3a1; margin-left:auto; background:#1e1e2e; padding:1px 6px; border-radius:3px; font-family:monospace; border:1px solid #45475a;"><?php echo esc_html($log->ip_address); ?></span>
                        <?php endif; ?>
                        </div>
                        <div style="margin-left:14px; display:flex; flex-wrap:wrap; gap:3px;">
                            <?php echo wp_kses($badges_html, ['span' => ['style' => [], 'class' => [], 'data-docs' => [], 'title' => []]]); ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p style="font-size:13px; color:#999; margin:0;"><?php esc_html_e('No scans yet. Click "Run Diagnosis" above.', 'pointnet-mailguard'); ?></p>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function analyzer_card(string $name, string $icon, $data, string $tab): void {
        $base_url = admin_url('admin.php?page=pn-mailguard&tab=' . $tab);
        if (!$data) {
            $bg = '#f8f8f8'; $border = '#e0e0e0'; $status_html = '<span style="font-size:12px; color:#999;">' . esc_html__('Not analyzed yet', 'pointnet-mailguard') . '</span>';
        } else {
        [$bg, $border, $status_html] = match ($data['status']) {
            'ok'      => ['#f6fff8', '#b8e6c1', '<span style="font-size:12px; font-weight:600; color:#00a32a;">✓ ' . esc_html__('All checks passed', 'pointnet-mailguard') . '</span>'],
            'warning' => ['#fffdf0', '#f0d080', '<span style="font-size:12px; font-weight:600; color:#996800;">⚠ ' . esc_html($data['warnings']) . ' ' . esc_html__('warnings', 'pointnet-mailguard') . '</span>'],
            default   => ['#fff8f8', '#f0b8b8', '<span style="font-size:12px; font-weight:600; color:#a30000;">✗ ' . esc_html($data['errors']) . ' ' . esc_html__('errors', 'pointnet-mailguard') . '</span>'],
        };
        }
        ?>
        <a href="<?php echo esc_url($base_url); ?>" style="text-decoration:none;">
            <div style="background:<?php echo esc_attr($bg); ?>; border:1px solid <?php echo esc_attr($border); ?>; border-radius:8px; padding:16px; cursor:pointer; transition:border-color 0.15s;">
                <div style="font-size:24px; margin-bottom:8px;"><?php echo esc_html($icon); ?></div>
                <p style="font-size:14px; font-weight:600; margin:0 0 6px; color:#1e1e1e;"><?php echo esc_html($name . ' Analyzer'); ?></p>
                <?php echo wp_kses($status_html, ['span' => ['style' => []]]); ?>
            </div>
        </a>
        <?php
    }

    /**
     * New combined monitor card: header + last scan status + run + edit buttons.
     */
    private static function monitor_card_v2(string $type, string $value, $last_log, ?string $domain): void {
        $is_email = ($type === 'email');
        $icon     = $is_email ? '📧' : '🌐';
        $title    = $is_email ? __('Email Monitor', 'pointnet-mailguard') : __('IP Monitor', 'pointnet-mailguard');
        $subtitle = $is_email
            ? __('Auto-detected mail server IP', 'pointnet-mailguard')
            : __('Manual IP address', 'pointnet-mailguard');
        $btn_id   = $is_email ? 'pn-dash-email-btn' : 'pn-dash-ip-btn';
        $edit_id  = $is_email ? 'pn-dash-email-edit' : 'pn-dash-ip-edit';
        $edit_form_id = $is_email ? 'pn-dash-email-edit-form' : 'pn-dash-ip-edit-form';
        $btn_label = $is_email
            ? __('📧 Run Email Diagnosis', 'pointnet-mailguard')
            : __('🌐 Run IP Diagnosis', 'pointnet-mailguard');
        $active   = $is_email
            ? (!empty($value) && is_email($value))
            : (!empty($value) && filter_var($value, FILTER_VALIDATE_IP));
        $disabled = !$active;
        $alert_email = get_option('pn_mailguard_email_alert', get_option('admin_email'));
        $tooltip_text = $is_email
            ? __('Auto-detects your mail server IP via MX lookup and runs full checks.', 'pointnet-mailguard')
            : __('Monitors a SEPARATE IP (your mail server is already covered by the email monitor above).', 'pointnet-mailguard');
        $tooltip_ip = '';
        if (!$is_email && !empty($value)) {
            $is_ipv4 = filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
            if ($is_ipv4) {
                $tooltip_ip = __('IPv4: DNSBL (9 blacklist) + PTR reverse DNS. For GeoIP and WHOIS use the DNS & IP Tools tab.', 'pointnet-mailguard');
            } else {
                $tooltip_ip = __('IPv6: PTR reverse DNS only. DNSBL checks are not available (only 1 of 9 blacklists supports IPv6). For GeoIP and WHOIS use the DNS & IP Tools tab.', 'pointnet-mailguard');
            }
        }
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; overflow:hidden;">
            <div style="background:#f8f8f8; border-bottom:1px solid #e0e0e0; padding:12px 16px; display:flex; align-items:center; gap:8px;">
                <span style="font-size:18px;"><?php echo esc_html($icon); ?></span>
                <span style="font-size:14px; font-weight:600;"><?php echo esc_html($title); ?></span>
                <span style="font-size:11px; color:#999; cursor:help; position:relative;"
                    title="<?php echo esc_attr($tooltip_text); ?><?php echo !empty($tooltip_ip) ? "\n\n" . esc_attr($tooltip_ip) : ''; ?>">ℹ️</span>
                <button type="button" id="<?php echo esc_attr($edit_id); ?>" class="button button-small button-secondary" style="margin-left:auto;" title="<?php esc_attr_e('Edit this monitor', 'pointnet-mailguard'); ?>">
                    ✏️
                </button>
            </div>
            <div style="padding:16px;">
                <!-- Inline edit form (hidden by default) -->
                <div id="<?php echo esc_attr($edit_form_id); ?>" style="display:none; margin-bottom:12px; background:#f8f8f8; border:1px solid #e0e0e0; border-radius:6px; padding:12px;">
                    <p style="font-size:12px; font-weight:600; margin:0 0 8px; color:#333;">
                        <?php esc_html_e('Edit monitor settings:', 'pointnet-mailguard'); ?>
                    </p>
                    <?php if ($is_email): ?>
                    <label style="font-size:11px; font-weight:600; display:block; margin-bottom:2px;">📧 <?php esc_html_e('Email da monitorare', 'pointnet-mailguard'); ?></label>
                    <input type="email" class="pn-edit-email" value="<?php echo esc_attr($value); ?>" placeholder="info@yourdomain.com" style="width:100%; padding:6px 8px; font-size:12px; margin-bottom:8px;">
                    <?php else: ?>
                    <label style="font-size:11px; font-weight:600; display:block; margin-bottom:2px;">🌐 <?php esc_html_e('IP Address', 'pointnet-mailguard'); ?></label>
                    <input type="text" class="pn-edit-ip" value="<?php echo esc_attr($value); ?>" placeholder="1.2.3.4" style="width:100%; padding:6px 8px; font-size:12px; margin-bottom:8px;">
                    <?php endif; ?>
                    <div style="display:flex; gap:6px;">
                        <button type="button" class="button button-primary button-small pn-edit-save" data-type="<?php echo esc_attr($type); ?>">
                            <?php esc_html_e('Save', 'pointnet-mailguard'); ?>
                        </button>
                        <button type="button" class="button button-secondary button-small pn-edit-cancel">
                            <?php esc_html_e('Cancel', 'pointnet-mailguard'); ?>
                        </button>
                        <span class="pn-edit-spinner" style="display:none; font-size:11px; color:#999; align-self:center;">⏳ <?php esc_html_e('Saving...', 'pointnet-mailguard'); ?></span>
                    </div>
                    <div class="pn-edit-msg" style="display:none; margin-top:6px; font-size:11px;"></div>
                </div>

                <?php if ($active): ?>
                <div class="pn-monitor-value" style="font-size:14px; color:#2271b1; font-weight:600; margin-bottom:6px;">
                    <?php echo esc_html($value); ?>
                    <?php if ($domain && $is_email): ?>
                    <span style="font-size:12px; color:#666; font-weight:400;">→ <?php echo esc_html($domain); ?></span>
                    <?php endif; ?>
                </div>
                <?php if ($is_email && $last_log && !empty($last_log->details)):
                    // Extract MX host and IP from log details
                    $mx_match = [];
                    preg_match('/MX:\s*([^\s]+)\s*\(([^)]+)\)/', $last_log->details, $mx_match);
                    if (!empty($mx_match[2])):
                ?>
                <div style="font-size:12px; color:#50575e; margin-bottom:10px; display:flex; align-items:center; gap:4px; flex-wrap:wrap;">
                    <span style="font-weight:600;">🔍 <?php esc_html_e('Auto-detected IP:', 'pointnet-mailguard'); ?></span>
                    <span style="font-family:monospace; background:#f0f0f1; padding:1px 6px; border-radius:3px; font-size:11px;"><?php echo esc_html($mx_match[2]); ?></span>
                    <span style="color:#999; font-size:11px;">
                        (<?php echo esc_html($mx_match[1]); ?> <?php esc_html_e('via MX lookup', 'pointnet-mailguard'); ?>)
                    </span>
                </div>
                <?php
                    endif;
                endif; ?>
                <?php else: ?>
                <p class="pn-monitor-value" style="font-size:13px; color:#999; margin:0 0 10px;">
                    <?php esc_html_e('Not configured. Click ✏️ to set up.', 'pointnet-mailguard'); ?>
                </p>
                <?php endif; ?>

                <?php if ($active && $last_log): ?>
                <div style="background:#1e1e2e; color:#cdd6f4; border-radius:6px; padding:10px 12px; margin-bottom:12px; font-family:monospace; font-size:11px; line-height:1.6;">
                    <div style="display:flex; align-items:center; gap:6px; margin-bottom:6px;">
                        <?php
                        $color = PN_Mailguard_Logger::status_color($last_log->status);
                        $alert = in_array($last_log->status, ['ALERT', 'ALERT + PTR', 'ERROR'], true);
                        $warn  = in_array($last_log->status, ['PTR WARNING', 'SPF WARNING'], true);
                        $icon2 = $alert ? '🔴' : ($warn ? '🟡' : '✅');
                        ?>
                        <span><?php echo esc_html($icon2); ?></span>
                        <span style="color:<?php echo esc_attr($color); ?>; font-weight:600;"><?php echo esc_html($last_log->status); ?></span>
                        <span style="color:#6c7086; margin-left:auto; font-size:10px;"><?php echo esc_html($last_log->scan_date); ?></span>
                    </div>
                    <div>
                        <?php echo wp_kses_post(PN_Mailguard_Logger::format_terminal_details($last_log->details)); ?>
                    </div>
                </div>
                <?php elseif ($active): ?>
                <p style="font-size:12px; color:#999; margin:0 0 12px;">
                    <?php esc_html_e('No scan results yet.', 'pointnet-mailguard'); ?>
                </p>
                <?php endif; ?>

                <button type="button" id="<?php echo esc_attr($btn_id); ?>" class="button button-secondary" style="width:100%; text-align:center;" <?php disabled($disabled); ?> title="">
                    <?php echo esc_html($btn_label); ?>
                </button>
            </div>
        </div>
        <?php
    }

    private static function get_last_log(string $type): ?object {
        global $wpdb;
        $table = $wpdb->prefix . ($type === 'ip' ? PN_Mailguard_Installer::TABLE_IP : PN_Mailguard_Installer::TABLE_EMAIL);
        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM %i ORDER BY scan_date DESC LIMIT %d",
                $table,
                1
            )
        );
    }

    // -------------------------------------------------------------------------
    // Full DNS analysis sections for Monitors tab
    // -------------------------------------------------------------------------

    private static function render_analyzer_section(string $type, string $icon, string $label, $data, string $domain, string $scan_date = ''): void {
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; overflow:hidden;">
            <div style="background:#f8f8f8; border-bottom:1px solid #e0e0e0; padding:12px 16px; display:flex; align-items:center; justify-content:space-between;">
                <span style="font-size:14px; font-weight:600; display:inline-flex; align-items:center; gap:4px;">
                    <span style="font-size:18px;"><?php echo esc_html($icon); ?></span>
                    <?php echo esc_html($label . ' Analyzer'); ?>
                    <button type="button" class="pn-doc-badge" data-docs="<?php echo esc_attr($type); ?>" style="background:none; border:none; color:#2271b1; cursor:pointer; font-size:13px; padding:0 2px; line-height:1;" title="<?php esc_attr_e('Contextual guide and documentation', 'pointnet-mailguard'); ?>">ℹ️</button>
                </span>
                <span style="font-size:11px; color:#999;">
                    <?php
                    esc_html_e('Last scan', 'pointnet-mailguard');
                    if (!empty($scan_date)) {
                        echo ' — ' . esc_html($scan_date);
                    }
                    ?>
                </span>
            </div>
            <div style="padding:16px;">
                <?php if (!$data): ?>
                    <p style="font-size:13px; color:#999; margin:0;"><?php esc_html_e('Not analyzed yet.', 'pointnet-mailguard'); ?></p>
                <?php else: ?>
                    <?php if (!empty($data['record'])): ?>
                    <div style="background:#1e1e2e; color:#a6e3a1; font-family:monospace; font-size:11px; padding:8px 10px; border-radius:4px; word-break:break-all; margin-bottom:12px; line-height:1.5;">
                        <?php echo esc_html($data['record']); ?>
                    </div>
                    <?php endif; ?>
                    <?php if (isset($data['passed'])): ?>
                    <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:6px; margin-bottom:12px;">
                        <?php self::dns_stat_card($data['passed'],   __('passed', 'pointnet-mailguard'),   '#00a32a'); ?>
                        <?php self::dns_stat_card($data['warnings'], __('warnings', 'pointnet-mailguard'), '#dba617'); ?>
                        <?php self::dns_stat_card($data['errors'],   __('errors', 'pointnet-mailguard'),   '#d63638'); ?>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($data['checks'])): ?>
                    <table style="width:100%; border-collapse:collapse; font-size:12px; table-layout:fixed;">
                        <?php foreach ($data['checks'] as $i => $c): ?>
                        <?php
                        $st = $c['status'];
                        $dotColor = match ($st) {
                            'ok'      => '#00a32a',
                            'warning' => '#dba617',
                            'info'    => '#2271b1',
                            default   => '#d63638',
                        };
                        $badgeText = match ($st) {
                            'ok'      => '✓ Pass',
                            'warning' => '⚠ Warning',
                            'info'    => 'ℹ Info',
                            default   => '✗ Error',
                        };
                        $badgeBg = match ($st) {
                            'ok'      => '#edfaef',
                            'warning' => '#fff8e5',
                            'info'    => '#e8f0fb',
                            default   => '#fbeaea',
                        };
                        $badgeColor = match ($st) {
                            'ok'      => '#00a32a',
                            'warning' => '#996800',
                            'info'    => '#2271b1',
                            default   => '#a30000',
                        };
                        $bg = $i % 2 === 0 ? '#fff' : '#fafafa';
                        ?>
                        <tr style="background:<?php echo esc_attr($bg); ?>; border-top:0.5px solid #e8e8e8;">
                            <td style="padding:6px 4px 6px 8px; width:10px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:<?php echo esc_attr($dotColor); ?>;"></span></td>
                            <td style="padding:6px 4px; font-weight:600; width:40%;"><?php echo esc_html($c['title']); ?></td>
                            <td style="padding:6px 4px; width:70px;"><span style="background:<?php echo esc_attr($badgeBg); ?>;color:<?php echo esc_attr($badgeColor); ?>;font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;"><?php echo esc_html($badgeText); ?></span></td>
                            <td style="padding:6px 4px; color:#555; line-height:1.4; word-break:break-word;"><?php echo esc_html($c['description']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </table>
                    <?php endif; ?>
                    <?php if (!empty($data['providers'])): ?>
                    <p style="font-size:11px; color:#666; margin:8px 0 0;"><?php esc_html_e('Detected providers:', 'pointnet-mailguard'); ?> <?php echo esc_html(implode(', ', $data['providers'])); ?></p>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    private static function dns_stat_card(int $num, string $label, string $color): void {
        echo '<div style="background:#f8f8f8;border-radius:4px;padding:8px;text-align:center;border:1px solid #e0e0e0;">'
            . '<div style="font-size:18px;font-weight:600;color:' . esc_attr($color) . ';">' . intval($num) . '</div>'
            . '<div style="font-size:10px;color:#666;margin-top:2px;">' . esc_html($label) . '</div></div>';
    }

    // -------------------------------------------------------------------------
    // AI Analysis card renderer
    // -------------------------------------------------------------------------

    private static function render_ai_card($ai_result): void {
        $report = json_decode($ai_result->report, true);
        if (empty($report)) {
            echo '<p style="font-size:13px; color:#999; margin:0;">' . esc_html__('AI report unavailable.', 'pointnet-mailguard') . '</p>';
            return;
        }

        $severity = $report['severity'] ?? 'warning';
        $score    = intval($report['score'] ?? 0);

        [$sev_color, $sev_bg, $sev_icon] = match ($severity) {
            'critical' => ['#d63638', '#fbeaea', '🔴'],
            'warning'  => ['#dba617', '#fff8e5', '🟡'],
            default    => ['#00a32a', '#edfaef', '🟢'],
        };
        ?>
        <div id="pn-ai-card" style="margin-top:12px;">
            <div style="display:flex; align-items:center; gap:12px; margin-bottom:12px; padding:10px; background:<?php echo esc_attr($sev_bg); ?>; border-radius:6px;">
                <div style="font-size:32px; font-weight:700; color:<?php echo esc_attr($sev_color); ?>;"><?php echo intval($score); ?></div>
                <div style="flex:1; font-size:13px; color:#333; line-height:1.4;">
                    <?php echo esc_html($report['summary_it'] ?? ''); ?>
                    <span style="font-size:11px; color:#999; margin-left:6px;"><?php echo esc_html($sev_icon . ' ' . ucfirst($severity)); ?></span>
                </div>
                <div style="font-size:11px; color:#999; white-space:nowrap;"><?php echo esc_html($ai_result->created_at); ?></div>
            </div>

            <?php if (!empty($report['issues'])): ?>
            <div style="margin-bottom:10px;">
                <?php foreach ($report['issues'] as $issue): ?>
                <?php
                $iss_sev = $issue['severity'] ?? 'info';
                [$iss_color, $iss_bg, $iss_icon] = match ($iss_sev) {
                    'error'   => ['#d63638', '#fbeaea', '🔴'],
                    'warning' => ['#dba617', '#fff8e5', '🟡'],
                    default   => ['#2271b1', '#e8f0fb', 'ℹ️'],
                };
                ?>
                <div style="padding:8px 10px; margin-bottom:4px; background:<?php echo esc_attr($iss_bg); ?>; border-radius:4px; font-size:12px;">
                    <div style="font-weight:600; color:<?php echo esc_attr($iss_color); ?>;">
                        <?php echo esc_html($iss_icon . ' [' . ($issue['component'] ?? 'GENERAL') . '] ' . ($issue['title'] ?? '')); ?>
                    </div>
                    <div style="color:#555; margin-top:2px;"><?php echo esc_html($issue['description'] ?? ''); ?></div>
                    <?php if (!empty($issue['fix'])): ?>
                    <div style="color:#2271b1; margin-top:2px;">💡 <?php echo esc_html($issue['fix']); ?></div>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>

            <?php if (!empty($report['strengths'])): ?>
            <div style="margin-bottom:10px;">
                <span style="font-size:12px; font-weight:600; color:#00a32a;">✅ <?php esc_html_e('Strengths', 'pointnet-mailguard'); ?></span>
                <ul style="margin:4px 0 0 16px; font-size:12px; color:#555;">
                    <?php foreach ($report['strengths'] as $s): ?>
                    <li><?php echo esc_html($s); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
            <?php endif; ?>

            <?php if (!empty($report['next_steps'])): ?>
            <div>
                <span style="font-size:12px; font-weight:600; color:#2271b1;">📋 <?php esc_html_e('Next steps', 'pointnet-mailguard'); ?></span>
                <ol style="margin:4px 0 0 16px; font-size:12px; color:#333;">
                    <?php foreach ($report['next_steps'] as $ns): ?>
                    <li style="margin-bottom:2px;"><?php echo esc_html($ns); ?></li>
                    <?php endforeach; ?>
                </ol>
            </div>
            <?php endif; ?>
        </div>
        <?php
    }

    // -------------------------------------------------------------------------
    // Dashboard JS
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // TAB: DNS Tools
    // -------------------------------------------------------------------------

    private static function render_dnstools(): void {
        $domain     = self::get_monitored_domain();
        $nonce      = wp_create_nonce('pn_mailguard_ajax_nonce');
        $dns_domain = get_option('pn_mailguard_analyze_domain', $domain);
        $saved_sel  = get_option('pn_mailguard_dkim_selector', '');
        ?>
        <div style="margin-bottom:20px;">
            <div class="card" style="padding:16px; max-width:600px;">
                <label for="pn-dns-domain" style="font-weight:600; font-size:14px;">
                    <?php esc_html_e('Domain to analyze', 'pointnet-mailguard'); ?>
                </label>
                <div style="display:flex; gap:8px; margin-top:8px;">
                    <input type="text" id="pn-dns-domain" value="<?php echo esc_attr($dns_domain); ?>" placeholder="yourdomain.com"
                        style="flex:1; padding:6px 10px; font-size:14px;"
                        <?php echo !empty($domain) ? 'data-auto="' . esc_attr($domain) . '"' : ''; ?>>
                    <button type="button" id="pn-dns-analyze-all" class="button button-primary">
                        🔬 <?php esc_html_e('Analyze All Records', 'pointnet-mailguard'); ?>
                    </button>
                </div>
                <p class="description" style="margin:6px 0 0;">
                    <?php esc_html_e('Enter any domain to check its SPF, DMARC and DKIM records at once.', 'pointnet-mailguard'); ?>
                    <?php if (!empty($domain)): ?>
                    <br><em><?php echo esc_html(sprintf(
                        /* translators: %s: domain name */
                        __('Auto-detected from Email Monitor: %s', 'pointnet-mailguard'),
                        $domain
                    )); ?></em>
                    <?php endif; ?>
                </p>
            </div>
        </div>

        <div id="pn-dkim-selector-row" style="display:none; margin-bottom:20px;">
            <div class="card" style="padding:16px; max-width:600px;">
                <label for="pn-dns-dkim-selector" style="font-weight:600; font-size:14px;">
                    🔑 <?php esc_html_e('DKIM Selector', 'pointnet-mailguard'); ?>
                </label>
                <div style="display:flex; gap:8px; margin-top:8px;">
                    <input type="text" id="pn-dns-dkim-selector" value="<?php echo esc_attr($saved_sel); ?>"
                        placeholder="<?php esc_attr_e('Leave empty to auto-detect', 'pointnet-mailguard'); ?>"
                        style="flex:1; padding:6px 10px; font-size:14px;">
                </div>
                <p class="description" style="margin:6px 0 0;">
                    <?php esc_html_e('Optional — if DKIM auto-detection fails, enter your selector manually.', 'pointnet-mailguard'); ?>
                </p>
            </div>
        </div>

        <div id="pn-dns-results">
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px,1fr)); gap:20px;">
                <?php
                self::render_dns_section('spf',    '🔐', 'SPF',    $nonce, $dns_domain);
                self::render_dns_section('dmarc',  '📋', 'DMARC',  $nonce, $dns_domain);
                self::render_dns_section('dkim',   '🔑', 'DKIM',   $nonce, $dns_domain);
                self::render_dns_section('mtasts', '🛡️', 'MTA-STS', $nonce, $dns_domain);
                self::render_dns_section('dnssec', '🔒', 'DNSSEC',  $nonce, $dns_domain);
                ?>
            </div>
        </div>

        <!-- 🌐 IP Analysis section -->
        <hr style="margin:32px 0 24px;">
        <h2 style="font-size:16px; margin:0 0 8px; color:#1d2327;">🌐 <?php esc_html_e('IP Analysis', 'pointnet-mailguard'); ?></h2>
        <p style="font-size:13px; color:#666; margin:0 0 16px;">
            <?php esc_html_e('Analyze any IPv4 or IPv6 address with PTR, GeoIP and WHOIS lookups. DNSBL checks require IPv4 (8 of 9 blacklists do not support IPv6).', 'pointnet-mailguard'); ?>
        </p>

        <div style="margin-bottom:20px;">
            <div class="card" style="padding:16px; max-width:600px;">
                <label for="pn-ip-address" style="font-weight:600; font-size:14px;">
                    <?php esc_html_e('IP address to analyze', 'pointnet-mailguard'); ?>
                </label>
                <div style="display:flex; gap:8px; margin-top:8px;">
                    <input type="text" id="pn-ip-address" value="" placeholder="1.2.3.4"
                        style="flex:1; padding:6px 10px; font-size:14px;">
                    <button type="button" id="pn-ip-analyze-all" class="button button-primary">
                        🔬 <?php esc_html_e('Analyze IP', 'pointnet-mailguard'); ?>
                    </button>
                </div>
                <p class="description" style="margin:6px 0 0;">
                    <?php esc_html_e('Enter any IPv4 address to check DNSBL blacklists, PTR record, geolocation and WHOIS info.', 'pointnet-mailguard'); ?>
                </p>
            </div>
        </div>

        <div id="pn-ip-results">
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px,1fr)); gap:20px;">
                <?php self::render_ip_section('dnsbl', '🚫', 'DNSBL', '9 ' . __('blacklists checked', 'pointnet-mailguard')); ?>
                <?php self::render_ip_section('ptr',   '↩️', 'PTR / ' . __('Reverse DNS', 'pointnet-mailguard'), __('Hostname lookup', 'pointnet-mailguard')); ?>
                <?php self::render_ip_section('geoip', '🌍', 'GeoIP', __('Location & ISP', 'pointnet-mailguard')); ?>
                <?php self::render_ip_section('whois', '📋', 'WHOIS', __('IP block info', 'pointnet-mailguard')); ?>
            </div>
        </div>

        <?php
    }

    private static function render_dns_section(string $type, string $icon, string $label, string $nonce, string $domain): void {
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; overflow:hidden;">
            <div style="background:#f8f8f8; border-bottom:1px solid #e0e0e0; padding:12px 16px; display:flex; align-items:center; justify-content:space-between;">
                <span style="font-size:14px; font-weight:600;">
                    <span style="font-size:18px;"><?php echo esc_html($icon); ?></span>
                    <?php echo esc_html($label); ?>
                </span>
                <?php if (!empty($domain)): ?>
                <button type="button" class="button button-small button-secondary pn-dns-single-btn" data-type="<?php echo esc_attr($type); ?>">
                    <?php esc_html_e('Analyze', 'pointnet-mailguard'); ?>
                </button>
                <?php endif; ?>
            </div>
            <div id="pn-dns-<?php echo esc_attr($type); ?>-body" style="padding:16px;">
                <p style="font-size:13px; color:#999; margin:0;">
                    <?php esc_html_e('Enter a domain and click "Analyze All Records".', 'pointnet-mailguard'); ?>
                </p>
            </div>
        </div>
        <?php
    }

    private static function render_ip_section(string $type, string $icon, string $label, string $subtitle): void {
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; overflow:hidden;">
            <div style="background:#f8f8f8; border-bottom:1px solid #e0e0e0; padding:12px 16px; display:flex; align-items:center; justify-content:space-between;">
                <span style="font-size:14px; font-weight:600;">
                    <span style="font-size:18px;"><?php echo esc_html($icon); ?></span>
                    <?php echo esc_html($label); ?>
                </span>
                <span style="font-size:11px; color:#999;">
                    <?php echo esc_html($subtitle); ?>
                </span>
            </div>
            <div id="pn-ip-<?php echo esc_attr($type); ?>-body" style="padding:16px;">
                <p style="font-size:13px; color:#999; margin:0;">
                    <?php esc_html_e('Enter an IP address and click "Analyze IP".', 'pointnet-mailguard'); ?>
                </p>
            </div>
        </div>
        <?php
    }

    // -------------------------------------------------------------------------
    // TAB: Advanced (only DKIM + Gemini config)
    // -------------------------------------------------------------------------

    private static function render_advanced(): void {
        $stored_key  = get_option('pn_mailguard_gemini_key', '');
        // Don't show the actual key (plaintext or encrypted) — display a placeholder if set
        $gemini_key  = !empty($stored_key) ? '********' : '';
        $gemini_model = get_option('pn_mailguard_gemini_model', '');
        $dkim_sel     = get_option('pn_mailguard_dkim_selector', '');
        $alert_email = get_option('pn_mailguard_email_alert', get_option('admin_email'));
        ?>
        <div class="card" style="padding:16px; max-width:800px;">
            <h2 style="margin-top:0;">🔑 <?php esc_html_e('DKIM Configuration', 'pointnet-mailguard'); ?></h2>
            <p><?php esc_html_e('The DKIM selector is used to automatically detect your DKIM DNS record. If auto-detection fails, you can set it here.', 'pointnet-mailguard'); ?></p>

            <form method="post">
                <?php wp_nonce_field('pn_mailguard_save_action', 'pn_mailguard_nonce'); ?>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="pn_mailguard_dkim_selector">🔑 <?php esc_html_e('DKIM Selector', 'pointnet-mailguard'); ?></label></th>
                        <td>
                            <input type="text" name="pn_mailguard_dkim_selector" id="pn_mailguard_dkim_selector"
                                value="<?php echo esc_attr($dkim_sel); ?>" class="regular-text" placeholder="<?php esc_attr_e('Leave empty to auto-detect', 'pointnet-mailguard'); ?>">
                            <p class="description"><?php esc_html_e('Optional. If DKIM auto-detection does not find your selector, enter it here. Common examples: google, selector1, mail, dkim.', 'pointnet-mailguard'); ?></p>
                        </td>
                    </tr>
                </table>

                <hr>

                <h2>📬 <?php esc_html_e('Alert Configuration', 'pointnet-mailguard'); ?></h2>
                <p><?php esc_html_e('Configure where and when to receive email notifications.', 'pointnet-mailguard'); ?></p>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="pn_mailguard_email_alert">📬 <?php esc_html_e('Alert Email', 'pointnet-mailguard'); ?></label></th>
                        <td>
                            <input type="email" name="pn_mailguard_email_alert" id="pn_mailguard_email_alert"
                                value="<?php echo esc_attr($alert_email); ?>" class="regular-text" placeholder="admin@yourdomain.com">
                            <p class="description">
                                <?php esc_html_e('Where to send email alerts when the monitors detect issues. This is a global setting shared by both Email and IP monitors.', 'pointnet-mailguard'); ?>
                                <?php if ($alert_email === get_option('admin_email')): ?>
                                <br><em><?php esc_html_e('Currently using the WordPress admin email. You can change it to any email address.', 'pointnet-mailguard'); ?></em>
                                <?php endif; ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="pn_mailguard_alert_level">📊 <?php esc_html_e('Notification Level', 'pointnet-mailguard'); ?></label></th>
                        <td>
                            <?php $alert_level = get_option('pn_mailguard_alert_level', 'all'); ?>
                            <select name="pn_mailguard_alert_level" id="pn_mailguard_alert_level" style="min-width:300px;">
                                <option value="all" <?php selected($alert_level, 'all'); ?>><?php esc_html_e('All issues (warnings + errors)', 'pointnet-mailguard'); ?></option>
                                <option value="errors" <?php selected($alert_level, 'errors'); ?>><?php esc_html_e('Errors only (DNSBL, DKIM errors, scan failures)', 'pointnet-mailguard'); ?></option>
                                <option value="none" <?php selected($alert_level, 'none'); ?>><?php esc_html_e('None (disable email notifications)', 'pointnet-mailguard'); ?></option>
                            </select>
                            <p class="description">
                                <?php esc_html_e('Choose which types of problems trigger an email notification. "Errors only" means you will only receive emails for critical problems like blacklist listings, DKIM errors, or scan failures — warnings like PTR or DMARC configuration suggestions will be shown only on the dashboard.', 'pointnet-mailguard'); ?>
                            </p>
                        </td>
                    </tr>
                </table>

                <hr>

                <h2>🤖 <?php esc_html_e('AI Configuration (Gemini API)', 'pointnet-mailguard'); ?></h2>
                <p><?php esc_html_e('Configure your Google Gemini API key and model for AI-powered deliverability analysis.', 'pointnet-mailguard'); ?></p>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="pn_mailguard_gemini_key"><?php esc_html_e('Gemini API Key', 'pointnet-mailguard'); ?></label></th>
                        <td>
                            <input type="password" name="pn_mailguard_gemini_key" id="pn_mailguard_gemini_key"
                                value="<?php echo esc_attr($gemini_key); ?>" class="regular-text" placeholder="AIza...">
                            <p class="description">
                                <?php esc_html_e('Get your free API key from', 'pointnet-mailguard'); ?>
                                <a href="https://aistudio.google.com/apikey" target="_blank">Google AI Studio</a>.
                                <?php esc_html_e('You can also define', 'pointnet-mailguard'); ?>
                                <code>PN_MAILGUARD_GEMINI_KEY</code> <?php esc_html_e('in wp-config.php.', 'pointnet-mailguard'); ?>
                            </p>
                            <div style="color:#dba617; background:#fff8e5; border-left:3px solid #dba617; padding:8px 10px; margin-top:8px; font-size:12px; border-radius:3px;">
                                ⚠️ <strong><?php esc_html_e('GDPR Notice:', 'pointnet-mailguard'); ?></strong>
                                <?php esc_html_e('Domain data (name, IP, DNS records) will be sent to Google Gemini API. By using an API key you accept', 'pointnet-mailguard'); ?>
                                <a href="https://ai.google.dev/terms" target="_blank"><?php esc_html_e('Google\'s terms', 'pointnet-mailguard'); ?></a>.
                                <?php esc_html_e('For full GDPR compliance use a paid Google Cloud account which includes a Data Processing Agreement.', 'pointnet-mailguard'); ?>
                            </div>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="pn_mailguard_gemini_model"><?php esc_html_e('AI Model', 'pointnet-mailguard'); ?></label></th>
                        <td>
                            <div style="display:flex; gap:6px; align-items:flex-start;">
                                <select name="pn_mailguard_gemini_model" id="pn_mailguard_gemini_model" style="min-width:300px;">
                                    <option value=""><?php esc_html_e('Default (gemini-3.1-flash-lite)', 'pointnet-mailguard'); ?></option>
                                    <?php
                                    $available = PN_Mailguard_AI::fetch_available_models();
                                    foreach ($available as $id => $display) {
                                        echo '<option value="' . esc_attr($id) . '" ' . selected($id, $gemini_model, false) . '>' . esc_html($display . ' (' . $id . ')') . '</option>';
                                    }
                                    ?>
                                </select>
                                <button type="button" id="pn-fetch-models-btn" class="button button-secondary">
                                    🔄 <?php esc_html_e('Fetch Models', 'pointnet-mailguard'); ?>
                                </button>
                            </div>
                            <p class="description">
                                <?php esc_html_e('Choose a model. You can also set', 'pointnet-mailguard'); ?>
                                <code>PN_MAILGUARD_GEMINI_MODEL</code> <?php esc_html_e('in wp-config.php.', 'pointnet-mailguard'); ?>
                                <?php if (empty($gemini_key)): ?>
                                <br><strong style="color:#d63638;"><?php esc_html_e('Save your AI API key first to see available models.', 'pointnet-mailguard'); ?></strong>
                                <?php endif; ?>
                            </p>
                            <div id="pn-fetch-models-status" style="font-size:11px; margin-top:4px;"></div>
                        </td>
                    </tr>
                </table>

                <hr>

                <h2>🗑️ <?php esc_html_e('Uninstall Behavior', 'pointnet-mailguard'); ?></h2>
                <p><?php esc_html_e('Choose what happens to plugin data when you delete the plugin from the Plugins screen.', 'pointnet-mailguard'); ?></p>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php esc_html_e('Data cleanup', 'pointnet-mailguard'); ?></th>
                        <td>
                            <label for="pn_mailguard_uninstall_cleanup">
                                <input type="checkbox" name="pn_mailguard_uninstall_cleanup" id="pn_mailguard_uninstall_cleanup" value="1" <?php checked(get_option('pn_mailguard_uninstall_cleanup', '1'), '1'); ?>>
                                <?php esc_html_e('Delete all data on uninstall', 'pointnet-mailguard'); ?>
                            </label>
                            <p class="description">
                                <?php esc_html_e('When enabled, all plugin tables, options and scheduled tasks will be removed when the plugin is deleted. Disable this to keep your data in the database if you plan to reinstall the plugin in the future.', 'pointnet-mailguard'); ?>
                            </p>
                        </td>
                    </tr>
                </table>

                <p class="submit">
                    <input type="submit" name="pn_mailguard_save_settings" class="button button-primary button-hero"
                        value="<?php esc_attr_e('Save Settings', 'pointnet-mailguard'); ?>">
                </p>
            </form>
        </div>

        <?php
    }

    // -------------------------------------------------------------------------
    // Shared AI sections (used by Monitors and Export / Support tabs)
    // -------------------------------------------------------------------------

    /**
     * Render the AI Deliverability Analysis section (button + result card).
     */
    private static function render_ai_analysis_section(): void {
        $domain = self::get_monitored_domain();
        if (empty($domain)) {
            echo '<p style="font-size:13px; color:#999; margin:0;">' . esc_html__('Configure an email monitor first to enable AI analysis.', 'pointnet-mailguard') . '</p>';
            return;
        }

        $gemini_key = get_option('pn_mailguard_gemini_key', '');
        $key_missing = empty($gemini_key);
        $advanced_url = admin_url('admin.php?page=pn-mailguard&tab=advanced');
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px;">
            <?php if ($key_missing): ?>
            <div style="color:#dba617; background:#fff8e5; border-left:3px solid #dba617; padding:10px 12px; margin-bottom:12px; font-size:12px; border-radius:3px;">
                ⚠️ <?php echo wp_kses(sprintf(
                    /* translators: %s: link to Advanced tab */
                    __('AI analysis requires a Gemini API key. Configure it in the <a href="%s" style="color:#2271b1; text-decoration:underline;">Advanced tab</a>.', 'pointnet-mailguard'),
                    esc_url($advanced_url)
                ), ['a' => ['href' => [], 'style' => [], 'target' => []]]); ?>
            </div>
            <?php endif; ?>

            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">
                <span style="font-size:14px; font-weight:600;">🤖 <?php esc_html_e('AI Deliverability Analysis', 'pointnet-mailguard'); ?></span>
                <button type="button" id="pn-ai-analyze-btn" class="button button-primary" <?php disabled($key_missing); ?>>
                    🤖 <?php esc_html_e('Analyze with AI', 'pointnet-mailguard'); ?>
                </button>
            </div>
            <div id="pn-ai-result">
                <?php
                $ai_result = PN_Mailguard_AI::get_latest($domain);
                if ($ai_result && !empty($ai_result->summary_it)) {
                    self::render_ai_card($ai_result);
                } else {
                    echo '<p style="font-size:13px; color:#999; margin:0;">' . esc_html__('Click "Analyze with AI" to get a full deliverability report with recommendations.', 'pointnet-mailguard') . '</p>';
                }
                ?>
            </div>
        </div>
        <?php
    }

    /**
     * Render the AI Chat section (chat messages + input).
     */
    private static function render_ai_chat_section(): void {
        $gemini_key = get_option('pn_mailguard_gemini_key', '');
        $key_missing = empty($gemini_key);
        $advanced_url = admin_url('admin.php?page=pn-mailguard&tab=advanced');
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px;">
            <?php if ($key_missing): ?>
            <div style="color:#dba617; background:#fff8e5; border-left:3px solid #dba617; padding:10px 12px; margin-bottom:12px; font-size:12px; border-radius:3px;">
                ⚠️ <?php echo wp_kses(sprintf(
                    /* translators: %s: link to Advanced tab */
                    __('AI chat requires a Gemini API key. Configure it in the <a href="%s" style="color:#2271b1; text-decoration:underline;">Advanced tab</a>.', 'pointnet-mailguard'),
                    esc_url($advanced_url)
                ), ['a' => ['href' => [], 'style' => [], 'target' => []]]); ?>
            </div>
            <?php endif; ?>

            <div style="display:flex; align-items:center; gap:8px; margin-bottom:12px;">
                <span style="font-size:16px;">💬</span>
                <span style="font-size:14px; font-weight:600;"><?php esc_html_e('Chat with AI', 'pointnet-mailguard'); ?></span>
                <span style="font-size:11px; color:#999;"><?php esc_html_e('Ask anything about email deliverability', 'pointnet-mailguard'); ?></span>
            </div>
            <div class="pn-chat-messages" style="max-height:400px; overflow-y:auto; margin-bottom:12px; padding:8px; background:#f8f8f8; border-radius:6px; min-height:60px; font-size:13px; line-height:1.5;">
                <p style="color:#999; margin:0; text-align:center;"><?php esc_html_e('Ask a question below to get started.', 'pointnet-mailguard'); ?></p>
            </div>
            <div style="display:flex; gap:8px;">
                <textarea class="pn-chat-input" style="flex:1; padding:8px 10px; font-size:13px; border:1px solid #dcdcde; border-radius:4px; resize:vertical; min-height:40px; max-height:120px;" placeholder="<?php esc_attr_e('e.g. Come posso configurare SPF per il mio dominio?', 'pointnet-mailguard'); ?>" <?php disabled($key_missing); ?>></textarea>
                <button type="button" class="button button-primary pn-chat-send-btn" style="align-self:flex-end;" <?php disabled($key_missing); ?>>
                    <?php esc_html_e('Send', 'pointnet-mailguard'); ?>
                </button>
            </div>
            <div class="pn-chat-error" style="display:none; color:#d63638; font-size:12px; margin-top:6px;"></div>
        </div>
        <?php
    }

    // -------------------------------------------------------------------------
    // TAB: Export / Support
    // -------------------------------------------------------------------------

    /**
     * Render the Export / Support tab.
     */
    private static function render_support(): void {
        $domain = self::get_monitored_domain();
        $check_email = get_option('pn_mailguard_check_email', '');
        $check_ip    = get_option('pn_mailguard_check_ip', '');
        ?>
        <!-- 📥 Export Report -->
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:20px; margin-bottom:24px;">
            <h2 style="font-size:16px; margin:0 0 12px;">📥 <?php esc_html_e('Export Diagnostic Report', 'pointnet-mailguard'); ?></h2>
            <p style="font-size:13px; color:#666; margin:0 0 16px;">
                <?php esc_html_e('Download a complete JSON report with all scan data, DNS configuration and settings. Share it with PointNet support or an external AI for troubleshooting.', 'pointnet-mailguard'); ?>
            </p>

            <!-- GDPR disclaimer -->
            <div style="color:#dba617; background:#fff8e5; border-left:3px solid #dba617; padding:10px 12px; margin-bottom:16px; font-size:12px; border-radius:3px;">
                ⚠️ <strong><?php esc_html_e('Privacy notice:', 'pointnet-mailguard'); ?></strong>
                <?php esc_html_e('The report contains your monitored email address and server IPs. Share it only with authorized personnel.', 'pointnet-mailguard'); ?>
            </div>

            <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
                <label style="font-size:13px; display:flex; align-items:center; gap:6px; cursor:pointer;">
                    <input type="checkbox" id="pn-export-anonymize" value="1">
                    <?php esc_html_e('Anonymize email/IP (replace with placeholders)', 'pointnet-mailguard'); ?>
                </label>
                <button type="button" id="pn-export-btn" class="button button-primary button-hero" style="margin-left:auto;">
                    📥 <?php esc_html_e('Download Report (JSON)', 'pointnet-mailguard'); ?>
                </button>
            </div>
        </div>

        <!-- 🤖 AI Deliverability Analysis -->
        <div id="pn-support-ai-section" style="margin-bottom:24px;">
            <?php self::render_ai_analysis_section(); ?>
        </div>

        <!-- 💬 Chat with AI -->
        <div id="pn-support-chat-section" style="margin-bottom:24px;">
            <?php self::render_ai_chat_section(); ?>
        </div>

        <!-- PointNet credit -->
        <div style="text-align:center; font-size:12px; color:#999; padding:12px;">
            <?php esc_html_e('by', 'pointnet-mailguard'); ?>
            <a href="https://www.pointnet.it/" target="_blank" style="color:#2271b1; text-decoration:none; font-weight:600;">PointNet</a>
        </div>

        <?php
    }

    /**
     * AJAX handler — generate and return the full export report JSON.
     */
    public static function ajax_export_report(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $anonymize = !empty($_POST['anonymize']);

        // Gather settings (never export API keys!)
        $check_email = get_option('pn_mailguard_check_email', '');
        $check_ip    = get_option('pn_mailguard_check_ip', '');
        $alert_email = get_option('pn_mailguard_email_alert', get_option('admin_email'));
        $dkim_sel    = get_option('pn_mailguard_dkim_selector', '');
        $domain      = self::get_monitored_domain();

        // Helper to anonymize
        $mask = function(string $value) use ($anonymize): string {
            if (!$anonymize || empty($value)) return $value;
            if (str_contains($value, '@')) {
                // Email: u***@domain.com
                $parts = explode('@', $value);
                $name  = substr($parts[0], 0, 1) . str_repeat('*', max(0, strlen($parts[0]) - 2)) . substr($parts[0], -1);
                return $name . '@' . $parts[1];
            }
            if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                // IP: 192.168.*.*
                $octets = explode('.', $value);
                return $octets[0] . '.' . $octets[1] . '.*.*';
            }
            return $value;
        };

        // DNS configuration via the single source of truth
        $dns_data = $domain ? PN_Mailguard_AI::build_report_data($domain, $check_email, $dkim_sel) : null;

        // Scan history
        $email_logs = PN_Mailguard_Logger::get_rows('email', 20);
        $ip_logs    = PN_Mailguard_Logger::get_rows('ip', 20);

        // AI analysis
        $ai_result = null;
        if ($domain) {
            $latest = PN_Mailguard_AI::get_latest($domain);
            if ($latest) {
                $ai_result = json_decode($latest->report, true);
            }
        }

        // Build report
        $report = [
            'generated_at'   => gmdate('Y-m-d\TH:i:s\Z'),
            'plugin_version' => PN_MAILGUARD_VERSION,
            'environment'    => [
                'wordpress_version' => get_bloginfo('version'),
                'php_version'       => PHP_VERSION,
                'site_url'          => get_site_url(),
                'admin_email'       => $alert_email,
            ],
            'settings'       => [
                'monitored_email' => $mask($check_email),
                'monitored_ip'    => $mask($check_ip),
                'alert_email'     => $alert_email,
                'domain'          => $domain,
                'dkim_selector'   => $dkim_sel,
                // API keys are intentionally NOT exported
            ],
            'dns_configuration' => [
                'domain'   => $domain,
                'spf'      => $dns_data['spf'] ?? null,
                'dmarc'    => $dns_data['dmarc'] ?? null,
                'dkim'     => $dns_data['dkim'] ?? null,
                'mtasts'   => $dns_data['mtasts'] ?? null,
                'dnssec'   => $dns_data['dnssec'] ?? null,
            ],
            'scan_history' => [
                'email_logs' => $email_logs ?: [],
                'ip_logs'    => $ip_logs ?: [],
            ],
            'ai_analysis' => $ai_result,
        ];

        wp_send_json_success($report);
    }

    // -------------------------------------------------------------------------
    // AJAX handlers
    // -------------------------------------------------------------------------

    public static function ajax_run_scheduled(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $lock = 'pn_mailguard_scan_lock';
        if (get_transient($lock)) {
            wp_send_json_error(['message' => __('Please wait 30 seconds between scans.', 'pointnet-mailguard')]);
        }
        set_transient($lock, true, 30);

        PN_Mailguard_Scanner::run_scheduled();

        wp_send_json_success(['message' => 'Scheduled scan completed.']);
    }

    public static function ajax_start_scan_email(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $lock = 'pn_mailguard_scan_lock';
        if (get_transient($lock)) {
            wp_send_json_error(['message' => __('Please wait 30 seconds between scans.', 'pointnet-mailguard')]);
        }
        set_transient($lock, true, 30);

        $email = get_option('pn_mailguard_check_email', '');
        if (empty($email)) {
            wp_send_json_error(['message' => 'No email configured.']);
        }

        $data = PN_Mailguard_Scanner::run_email($email);
        PN_Mailguard_Logger::save($data, 'email');
        PN_Mailguard_Mailer::maybe_send($data, 'email');

        // Populate DNS cache for the Monitors tab analyzers
        $dkim_sel = get_option('pn_mailguard_dkim_selector', '');
        PN_Mailguard_Scanner::cache_dns_analysis($email, $dkim_sel);

        wp_send_json_success();
    }

    public static function ajax_start_scan_ip(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $lock = 'pn_mailguard_scan_lock';
        if (get_transient($lock)) {
            wp_send_json_error(['message' => __('Please wait 30 seconds between scans.', 'pointnet-mailguard')]);
        }
        set_transient($lock, true, 30);

        $ip = get_option('pn_mailguard_check_ip', '');
        if (empty($ip)) {
            wp_send_json_error(['message' => 'No IP configured.']);
        }

        $data = PN_Mailguard_Scanner::run_ip($ip);
        PN_Mailguard_Logger::save($data, 'ip');
        PN_Mailguard_Mailer::maybe_send($data, 'ip');

        wp_send_json_success();
    }

    public static function ajax_refresh_logs_email(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        ob_start();
        PN_Mailguard_Logger::render_rows('email');
        $html = ob_get_clean();

        wp_send_json_success($html);
    }

    public static function ajax_refresh_logs_ip(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        ob_start();
        PN_Mailguard_Logger::render_rows('ip');
        $html = ob_get_clean();

        wp_send_json_success($html);
    }

    public static function ajax_analyze_spf(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $domain = isset($_POST['domain']) ? sanitize_text_field(wp_unslash($_POST['domain'])) : '';
        if (empty($domain)) {
            wp_send_json_error(['message' => 'Domain is required.']);
        }

        $result = PN_Mailguard_SPF::analyze($domain);
        wp_send_json_success($result);
    }

    public static function ajax_analyze_dmarc(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $domain = isset($_POST['domain']) ? sanitize_text_field(wp_unslash($_POST['domain'])) : '';
        if (empty($domain)) {
            wp_send_json_error(['message' => 'Domain is required.']);
        }

        $result = PN_Mailguard_DMARC::analyze($domain);
        wp_send_json_success($result);
    }

    public static function ajax_analyze_dkim(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $domain   = isset($_POST['domain']) ? sanitize_text_field(wp_unslash($_POST['domain'])) : '';
        $selector = isset($_POST['selector']) ? sanitize_text_field(wp_unslash($_POST['selector'])) : '';

        if (empty($domain)) {
            wp_send_json_error(['message' => 'Domain is required.']);
        }

        $autodetected = false;

        if (empty($selector)) {
            $d = PN_Mailguard_DKIM::autodetect($domain);
            if (!empty($d['selector'])) {
                $selector     = $d['selector'];
                $autodetected = true;
            }
        }

        if (empty($selector)) {
            wp_send_json_error(['message' => 'No DKIM selector found. Enter one manually.']);
        }

        $result = PN_Mailguard_DKIM::analyze($domain, $selector);
        $result['autodetected'] = $autodetected;

        wp_send_json_success($result);
    }

    public static function ajax_analyze_mtasts(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $domain = isset($_POST['domain']) ? sanitize_text_field(wp_unslash($_POST['domain'])) : '';
        if (empty($domain)) {
            wp_send_json_error(['message' => 'Domain is required.']);
        }

        $result = PN_Mailguard_MTA_STS::analyze($domain);
        wp_send_json_success($result);
    }

    public static function ajax_analyze_dnssec(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $domain = isset($_POST['domain']) ? sanitize_text_field(wp_unslash($_POST['domain'])) : '';
        if (empty($domain)) {
            wp_send_json_error(['message' => 'Domain is required.']);
        }

        $result = PN_Mailguard_Dnssec::analyze($domain);
        wp_send_json_success($result);
    }

    public static function ajax_fetch_models(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        // Clear cache first, then fetch fresh models
        PN_Mailguard_AI::clear_models_cache();
        $models = PN_Mailguard_AI::fetch_available_models();
        wp_send_json_success($models);
    }

    public static function ajax_ai_chat(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $question = isset($_POST['question']) ? sanitize_text_field(wp_unslash($_POST['question'])) : '';
        if (empty($question)) {
            wp_send_json_error(['message' => 'Question is required.']);
        }

        $domain  = self::get_monitored_domain();
        $email   = get_option('pn_mailguard_check_email', '');
        $sel_opt = get_option('pn_mailguard_dkim_selector', '');

        $response = PN_Mailguard_AI::chat($question, $domain, $email, $sel_opt);

        if (str_contains($response, 'AI not configured') || str_contains($response, 'Gemini API')) {
            wp_send_json_error(['message' => $response]);
        } else {
            wp_send_json_success(['response' => $response]);
        }
    }

    public static function ajax_ai_analyze(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $domain  = self::get_monitored_domain();
        $email   = get_option('pn_mailguard_check_email', '');
        $sel_opt = get_option('pn_mailguard_dkim_selector', '');

        if (empty($domain)) {
            wp_send_json_error(['message' => 'No domain configured.']);
        }

        $result = PN_Mailguard_AI::analyze($email, $domain, $sel_opt);

        if (!empty($result['error'])) {
            wp_send_json_error(['message' => $result['error_msg'] ?? 'AI analysis failed.']);
        }

        wp_send_json_success($result);
    }

    // -------------------------------------------------------------------------
    // AJAX — IP Analysis tools
    // -------------------------------------------------------------------------

    public static function ajax_ip_dnsbl(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        if (empty($ip)) {
            wp_send_json_error(['message' => 'IP address is required.']);
        }

        $result = PN_Mailguard_DNSBL::check($ip);
        wp_send_json_success($result);
    }

    public static function ajax_ip_ptr(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        if (empty($ip)) {
            wp_send_json_error(['message' => 'IP address is required.']);
        }

        $result = PN_Mailguard_PTR::check($ip);
        wp_send_json_success($result);
    }

    public static function ajax_ip_geoip(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        if (empty($ip)) {
            wp_send_json_error(['message' => 'IP address is required.']);
        }

        $result = PN_Mailguard_GeoIP::lookup($ip);
        wp_send_json_success($result);
    }

    public static function ajax_ip_whois(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        if (empty($ip)) {
            wp_send_json_error(['message' => 'IP address is required.']);
        }

        $result = PN_Mailguard_Whois::lookup($ip);
        wp_send_json_success($result);
    }

    // -------------------------------------------------------------------------
    // TAB: DMARC & TLS Reports
    // -------------------------------------------------------------------------

    private static function render_dmarcreports(): void {
        global $wpdb;
        $table_dmarc_rep = $wpdb->prefix . PN_Mailguard_Installer::TABLE_DMARC_REPORTS;
        $table_dmarc_rec = $wpdb->prefix . PN_Mailguard_Installer::TABLE_DMARC_RECORDS;
        $table_tls_rep   = $wpdb->prefix . PN_Mailguard_Installer::TABLE_TLS_REPORTS;
        $table_tls_rec   = $wpdb->prefix . PN_Mailguard_Installer::TABLE_TLS_RECORDS;

        // DMARC stats
        $dmarc_stats = $wpdb->get_row($wpdb->prepare("SELECT COUNT(id) as count_reports, SUM(total_messages) as total_msg, SUM(passed_messages) as passed_msg, SUM(failed_messages) as failed_msg FROM %i", $table_dmarc_rep));
        $dmarc_count_reports = intval($dmarc_stats->count_reports ?? 0);
        $dmarc_total_msg     = intval($dmarc_stats->total_msg ?? 0);
        $dmarc_passed_msg    = intval($dmarc_stats->passed_msg ?? 0);
        $dmarc_failed_msg    = intval($dmarc_stats->failed_msg ?? 0);
        $dmarc_pass_rate     = $dmarc_total_msg > 0 ? round(($dmarc_passed_msg / $dmarc_total_msg) * 100, 1) : 0.0;

        // TLS stats
        $tls_stats = $wpdb->get_row($wpdb->prepare("SELECT COUNT(id) as count_reports, SUM(successful_sessions) as total_success, SUM(failed_sessions) as total_failed FROM %i", $table_tls_rep));
        $tls_count_reports   = intval($tls_stats->count_reports ?? 0);
        $tls_total_success   = intval($tls_stats->total_success ?? 0);
        $tls_total_failed    = intval($tls_stats->total_failed ?? 0);
        $tls_total_sessions  = $tls_total_success + $tls_total_failed;
        $tls_success_rate    = $tls_total_sessions > 0 ? round(($tls_total_success / $tls_total_sessions) * 100, 1) : 100.0;

        $dmarc_reports = $wpdb->get_results($wpdb->prepare("SELECT * FROM %i ORDER BY created_at DESC LIMIT %d", $table_dmarc_rep, 50));
        $tls_reports   = $wpdb->get_results($wpdb->prepare("SELECT * FROM %i ORDER BY created_at DESC LIMIT %d", $table_tls_rep, 50));
        $monitored_domain = self::get_monitored_domain();
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:20px; margin-bottom:24px;">
            <h2 style="font-size:18px; margin:0 0 8px; color:#1d2327; display:flex; align-items:center; gap:8px;">
                📊 <?php esc_html_e('DMARC & TLS Aggregate Reports Reader', 'pointnet-mailguard'); ?>
            </h2>
            <p style="font-size:13px; color:#50575e; margin:0 0 16px; line-height:1.5;">
                <?php esc_html_e('Upload DMARC aggregate report files (.xml, .gz, .zip) and TLSRPT TLS reports (.json, .json.gz, .zip) sent by Gmail, Outlook, Yahoo, etc. PointNet Mail Guard automatically uncompresses, detects and stores full email authentication and MTA-STS TLS delivery analytics.', 'pointnet-mailguard'); ?>
            </p>

            <!-- Upload Area -->
            <div id="pn-dmarc-dropzone" style="border:2px dashed #2271b1; background:#f0f6ff; border-radius:8px; padding:24px; text-align:center; transition:background 0.2s; cursor:pointer;">
                <div style="font-size:36px; margin-bottom:8px;">📂</div>
                <p style="font-size:15px; font-weight:600; margin:0 0 4px; color:#1d2327;">
                    <?php esc_html_e('Drag & drop DMARC (.xml) or TLSRPT (.json) report files here, or click to browse', 'pointnet-mailguard'); ?>
                </p>
                <p style="font-size:12px; color:#666; margin:0 0 16px;">
                    <?php esc_html_e('Supported formats: DMARC XML (.xml, .gz, .zip) and TLSRPT JSON (.json, .json.gz, .gz, .zip)', 'pointnet-mailguard'); ?>
                </p>

                <form id="pn-dmarc-upload-form" style="display:inline-block;">
                    <input type="file" id="pn-dmarc-file-input" name="dmarc_file[]" accept=".xml,.json,.gz,.zip" multiple style="display:none;">
                    <button type="button" id="pn-dmarc-browse-btn" class="button button-primary button-hero">
                        📤 <?php esc_html_e('Select DMARC / TLSRPT Report Files', 'pointnet-mailguard'); ?>
                    </button>
                </form>

                <div id="pn-dmarc-upload-status" style="margin-top:12px; font-size:13px; font-weight:600; display:none;"></div>
            </div>

            <!-- IMAP Automatic Fetcher Accordion / Card -->
            <?php
            $imap_cfg = PN_Mailguard_Imap_Fetcher::get_config();
            $last_time = get_option('pn_mailguard_imap_last_fetch_time', '');
            $last_summary = get_option('pn_mailguard_imap_last_fetch_summary', []);
            ?>
            <div style="margin-top:20px; background:#f8f9fa; border:1px solid #dcdcde; border-radius:6px; padding:16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h3 style="font-size:14px; margin:0; color:#1d2327; display:flex; align-items:center; gap:6px;">
                        📬 <?php esc_html_e('Automatic Email Ingestion (IMAP Mailbox)', 'pointnet-mailguard'); ?>
                        <?php if ($imap_cfg['auto_fetch']): ?>
                            <span style="background:#edfaef; color:#00a32a; font-size:11px; font-weight:700; padding:2px 8px; border-radius:10px;">
                                ACTIVE (HOURLY)
                            </span>
                        <?php else: ?>
                            <span style="background:#f0f0f1; color:#666; font-size:11px; font-weight:600; padding:2px 8px; border-radius:10px;">
                                DISABLED
                            </span>
                        <?php endif; ?>
                    </h3>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <button type="button" id="pn-reset-dmarc-btn" class="button button-link-delete button-small" style="color:#d63638; display:inline-flex; align-items:center; gap:4px; text-decoration:none;">
                            🗑️ <?php esc_html_e('Empty Database (DMARC & TLS)', 'pointnet-mailguard'); ?>
                        </button>
                        <button type="button" id="pn-imap-fetch-btn" class="button button-secondary button-small" style="display:inline-flex; align-items:center; gap:4px;">
                            🔄 <?php esc_html_e('Fetch Reports Now', 'pointnet-mailguard'); ?>
                        </button>
                    </div>
                </div>

                <p style="font-size:12px; color:#666; margin:0 0 12px;">
                    <?php esc_html_e('Configure a dedicated mailbox (e.g. dmarc-reports@domain.com) to automatically download and process incoming DMARC and TLSRPT report attachments.', 'pointnet-mailguard'); ?>
                </p>

                <form method="post" action="" id="pn-imap-settings-form">
                    <?php wp_nonce_field('pn_mailguard_save_action', 'pn_mailguard_nonce'); ?>
                    <input type="hidden" name="pn_mailguard_save_settings" value="1">

                    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:12px; margin-bottom:12px;">
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:4px;"><?php esc_html_e('IMAP Host', 'pointnet-mailguard'); ?></label>
                            <input type="text" id="pn_imap_host" name="pn_mailguard_imap_host" value="<?php echo esc_attr($imap_cfg['host']); ?>" placeholder="mail.yourdomain.com" style="width:100%; font-size:12px;">
                        </div>
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:4px;"><?php esc_html_e('Port', 'pointnet-mailguard'); ?></label>
                            <input type="number" id="pn_imap_port" name="pn_mailguard_imap_port" value="<?php echo esc_attr($imap_cfg['port']); ?>" placeholder="993" style="width:100%; font-size:12px;">
                        </div>
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:4px;"><?php esc_html_e('Encryption', 'pointnet-mailguard'); ?></label>
                            <select id="pn_imap_encryption" name="pn_mailguard_imap_encryption" style="width:100%; font-size:12px;">
                                <option value="ssl" <?php selected($imap_cfg['encryption'], 'ssl'); ?>>SSL / TLS (Port 993)</option>
                                <option value="tls" <?php selected($imap_cfg['encryption'], 'tls'); ?>>STARTTLS (Port 143)</option>
                                <option value="none" <?php selected($imap_cfg['encryption'], 'none'); ?>>None (Plaintext)</option>
                            </select>
                        </div>
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:4px;"><?php esc_html_e('Username / Email', 'pointnet-mailguard'); ?></label>
                            <input type="text" id="pn_imap_username" name="pn_mailguard_imap_username" value="<?php echo esc_attr($imap_cfg['username']); ?>" placeholder="dmarc@yourdomain.com" style="width:100%; font-size:12px;">
                        </div>
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:4px;"><?php esc_html_e('Password', 'pointnet-mailguard'); ?></label>
                            <input type="password" id="pn_imap_password" name="pn_mailguard_imap_password" value="<?php echo !empty($imap_cfg['password']) ? '********' : ''; ?>" placeholder="••••••••" style="width:100%; font-size:12px;">
                        </div>
                        <div>
                            <label style="font-size:11px; font-weight:600; color:#555; display:block; margin-bottom:4px;"><?php esc_html_e('Mailbox Folder', 'pointnet-mailguard'); ?></label>
                            <input type="text" id="pn_imap_mailbox" name="pn_mailguard_imap_mailbox" value="<?php echo esc_attr($imap_cfg['mailbox']); ?>" placeholder="INBOX" style="width:100%; font-size:12px;">
                        </div>
                    </div>

                    <div style="display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:12px; background:#fff; padding:10px 12px; border:1px solid #e0e0e0; border-radius:4px;">
                        <div style="display:flex; align-items:center; gap:16px;">
                            <label style="font-size:12px; font-weight:600; display:inline-flex; align-items:center; gap:6px; cursor:pointer;">
                                <input type="checkbox" name="pn_mailguard_imap_auto_fetch" value="1" <?php checked($imap_cfg['auto_fetch']); ?>>
                                <?php esc_html_e('Enable automatic hourly polling (WP-Cron)', 'pointnet-mailguard'); ?>
                            </label>

                            <label style="font-size:12px; color:#555; display:inline-flex; align-items:center; gap:6px;">
                                <span><?php esc_html_e('Action after import:', 'pointnet-mailguard'); ?></span>
                                <select name="pn_mailguard_imap_action_after" style="font-size:12px;">
                                    <option value="delete" <?php selected($imap_cfg['action_after'], 'delete'); ?>><?php esc_html_e('Delete email from server (Recommended for dedicated mailboxes)', 'pointnet-mailguard'); ?></option>
                                    <option value="mark_read" <?php selected($imap_cfg['action_after'], 'mark_read'); ?>><?php esc_html_e('Mark as read (\Seen)', 'pointnet-mailguard'); ?></option>
                                </select>
                            </label>
                        </div>

                        <div style="display:flex; align-items:center; gap:8px;">
                            <button type="button" id="pn-imap-test-btn" class="button button-secondary">
                                🔌 <?php esc_html_e('Test Connection', 'pointnet-mailguard'); ?>
                            </button>
                            <button type="submit" class="button button-primary">
                                💾 <?php esc_html_e('Save IMAP Settings', 'pointnet-mailguard'); ?>
                            </button>
                        </div>
                    </div>
                </form>

                <div id="pn-imap-status" style="margin-top:10px; font-size:12px; font-weight:600; display:none;"></div>

                <?php if (!empty($last_time)): ?>
                    <div style="margin-top:10px; font-size:11px; color:#666;">
                        <strong>Last fetch:</strong> <?php echo esc_html($last_time); ?>
                        <?php if (is_array($last_summary)): ?>
                            | Imported: <strong><?php echo esc_html($last_summary['imported'] ?? 0); ?></strong>,
                            Duplicates skipped: <strong><?php echo esc_html($last_summary['duplicates'] ?? 0); ?></strong>,
                            Failed: <strong><?php echo esc_html($last_summary['failed'] ?? 0); ?></strong>
                        <?php endif; ?>
                    </div>
                    <?php if (is_array($last_summary)): ?>
                        <?php if (!empty($last_summary['imported_list'])): ?>
                            <div style="margin-top:6px; padding:6px 10px; background:#edfaef; border:1px solid #c3e6cb; border-radius:4px; font-size:11px; color:#00a32a; max-height:140px; overflow-y:auto;">
                                <strong>📥 <?php esc_html_e('Imported Reports:', 'pointnet-mailguard'); ?></strong>
                                <ul style="margin:2px 0 0 16px; padding:0; list-style-type:disc;">
                                    <?php foreach ($last_summary['imported_list'] as $item): ?>
                                        <li><?php echo esc_html($item); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif; ?>
                        <?php if (!empty($last_summary['duplicates_list'])): ?>
                            <div style="margin-top:6px; padding:6px 10px; background:#fff8e5; border:1px solid #ffeeba; border-radius:4px; font-size:11px; color:#856404; max-height:140px; overflow-y:auto;">
                                <strong>⏭️ <?php esc_html_e('Duplicates Skipped (Report IDs already present):', 'pointnet-mailguard'); ?></strong>
                                <ul style="margin:2px 0 0 16px; padding:0; list-style-type:disc;">
                                    <?php foreach ($last_summary['duplicates_list'] as $item): ?>
                                        <li><?php echo esc_html($item); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif; ?>
                        <?php if (!empty($last_summary['errors'])): ?>
                            <div style="margin-top:6px; padding:6px 10px; background:#fbeaea; border:1px solid #f5c6cb; border-radius:4px; font-size:11px; color:#d63638; max-height:140px; overflow-y:auto;">
                                <strong>❌ <?php esc_html_e('Fetch Errors:', 'pointnet-mailguard'); ?></strong>
                                <ul style="margin:2px 0 0 16px; padding:0; list-style-type:disc;">
                                    <?php foreach ($last_summary['errors'] as $err): ?>
                                        <li><?php echo esc_html($err); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>

        <!-- RUA & TLSRPT Helper Box -->
        <div style="background:#fff8e5; border:1px solid #f0d080; border-radius:8px; padding:16px; margin-bottom:24px;">
            <div style="display:flex; align-items:flex-start; gap:12px;">
                <span style="font-size:24px;">💡</span>
                <div style="flex:1;">
                    <h3 style="font-size:14px; font-weight:600; margin:0 0 6px; color:#996800;">
                        <?php esc_html_e('How to receive automatic DMARC and TLSRPT reports', 'pointnet-mailguard'); ?>
                    </h3>
                    <p style="font-size:12px; color:#555; margin:0 0 10px; line-height:1.4;">
                        <?php esc_html_e('To enable automatic reporting from major email receivers (Google, Microsoft, Yahoo), publish the following DNS TXT records for your domain:', 'pointnet-mailguard'); ?>
                    </p>
                    
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
                        <div>
                            <strong style="font-size:11px; color:#666; text-transform:uppercase;"><?php esc_html_e('1. DMARC Aggregate Reports (RFC 7489)', 'pointnet-mailguard'); ?>:</strong>
                            <div style="background:#fff; border:1px solid #e0e0e0; padding:8px 12px; border-radius:4px; font-family:monospace; font-size:11px; color:#1d2327; margin-top:4px; word-break:break-all;">
                                _dmarc<?php echo $monitored_domain ? '.' . esc_html($monitored_domain) : ''; ?> TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@<?php echo $monitored_domain ? esc_html($monitored_domain) : 'yourdomain.com'; ?>;"
                            </div>
                        </div>
                        <div>
                            <strong style="font-size:11px; color:#666; text-transform:uppercase;"><?php esc_html_e('2. MTA-STS TLS Reports (RFC 8460)', 'pointnet-mailguard'); ?>:</strong>
                            <div style="background:#fff; border:1px solid #e0e0e0; padding:8px 12px; border-radius:4px; font-family:monospace; font-size:11px; color:#1d2327; margin-top:4px; word-break:break-all;">
                                _smtp._tls<?php echo $monitored_domain ? '.' . esc_html($monitored_domain) : ''; ?> TXT "v=TLSRPTv1; rua=mailto:tls-reports@<?php echo $monitored_domain ? esc_html($monitored_domain) : 'yourdomain.com'; ?>;"
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Global Summary Statistics -->
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:16px; margin-bottom:24px;">
            <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px; text-align:center;">
                <div style="font-size:26px; font-weight:700; color:#2271b1;"><?php echo esc_html(number_format_i18n($dmarc_count_reports + $tls_count_reports)); ?></div>
                <div style="font-size:12px; color:#666; margin-top:4px; font-weight:600;"><?php esc_html_e('Total Reports Imported', 'pointnet-mailguard'); ?></div>
            </div>
            <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px; text-align:center;">
                <div style="font-size:26px; font-weight:700; color:#1d2327;"><?php echo esc_html(number_format_i18n($dmarc_total_msg)); ?></div>
                <div style="font-size:12px; color:#666; margin-top:4px; font-weight:600;"><?php esc_html_e('DMARC Evaluated Emails', 'pointnet-mailguard'); ?></div>
            </div>
            <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px; text-align:center;">
                <div style="font-size:26px; font-weight:700; color:<?php echo esc_attr($dmarc_pass_rate >= 90 ? '#00a32a' : ($dmarc_pass_rate >= 70 ? '#dba617' : '#d63638')); ?>;">
                    <?php echo esc_html($dmarc_pass_rate); ?>%
                </div>
                <div style="font-size:12px; color:#666; margin-top:4px; font-weight:600;"><?php esc_html_e('DMARC Pass Rate', 'pointnet-mailguard'); ?></div>
            </div>
            <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px; text-align:center;">
                <div style="font-size:26px; font-weight:700; color:#1d2327;"><?php echo esc_html(number_format_i18n($tls_total_sessions)); ?></div>
                <div style="font-size:12px; color:#666; margin-top:4px; font-weight:600;"><?php esc_html_e('MTA-STS TLS Sessions', 'pointnet-mailguard'); ?></div>
            </div>
            <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px; text-align:center;">
                <div style="font-size:26px; font-weight:700; color:<?php echo esc_attr($tls_success_rate >= 95 ? '#00a32a' : ($tls_success_rate >= 80 ? '#dba617' : '#d63638')); ?>;">
                    <?php echo esc_html($tls_success_rate); ?>%
                </div>
                <div style="font-size:12px; color:#666; margin-top:4px; font-weight:600;"><?php esc_html_e('TLS Delivery Success', 'pointnet-mailguard'); ?></div>
            </div>
        </div>

        <!-- Section 1: DMARC Reports -->
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:20px; margin-bottom:24px;">
            <h3 style="font-size:15px; margin:0 0 16px; color:#1d2327;">✉️ <?php esc_html_e('DMARC Aggregate Reports (RFC 7489)', 'pointnet-mailguard'); ?></h3>

            <?php if (empty($dmarc_reports)): ?>
                <p style="font-size:13px; color:#999; text-align:center; padding:20px 0; margin:0;">
                    <?php esc_html_e('No DMARC reports imported yet. Use the upload box above to upload your first report file.', 'pointnet-mailguard'); ?>
                </p>
            <?php else: ?>
                <table class="wp-list-table widefat fixed striped" style="border:none;">
                    <thead>
                        <tr>
                            <th style="width:180px;"><?php esc_html_e('Reporting Org', 'pointnet-mailguard'); ?></th>
                            <th><?php esc_html_e('Domain', 'pointnet-mailguard'); ?></th>
                            <th style="width:180px;"><?php esc_html_e('Date Range', 'pointnet-mailguard'); ?></th>
                            <th style="width:100px; text-align:center;"><?php esc_html_e('Total Emails', 'pointnet-mailguard'); ?></th>
                            <th style="width:100px; text-align:center;"><?php esc_html_e('Pass Rate', 'pointnet-mailguard'); ?></th>
                            <th style="width:130px; text-align:center;"><?php esc_html_e('Imported On', 'pointnet-mailguard'); ?></th>
                            <th style="width:120px; text-align:right;"><?php esc_html_e('Actions', 'pointnet-mailguard'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($dmarc_reports as $rep):
                            $records = $wpdb->get_results($wpdb->prepare("SELECT * FROM %i WHERE report_id_fk = %d ORDER BY count DESC", $table_dmarc_rec, $rep->id));
                        ?>
                        <tr>
                            <td>
                                <strong>🏢 <?php echo esc_html($rep->org_name); ?></strong>
                                <div style="font-size:10px; color:#999; font-family:monospace;"><?php echo esc_html($rep->report_id); ?></div>
                            </td>
                            <td><code><?php echo esc_html($rep->domain); ?></code></td>
                            <td style="font-size:11px; color:#666;">
                                <?php echo esc_html($rep->date_begin ? substr($rep->date_begin, 0, 10) : 'N/A'); ?> → 
                                <?php echo esc_html($rep->date_end ? substr($rep->date_end, 0, 10) : 'N/A'); ?>
                            </td>
                            <td style="text-align:center;"><strong><?php echo esc_html(number_format_i18n($rep->total_messages)); ?></strong></td>
                            <td style="text-align:center;">
                                <?php
                                $rate = floatval($rep->pass_rate);
                                $badge_bg = $rate >= 90 ? '#edfaef' : ($rate >= 70 ? '#fff8e5' : '#fbeaea');
                                $badge_color = $rate >= 90 ? '#00a32a' : ($rate >= 70 ? '#996800' : '#a30000');
                                ?>
                                <span style="background:<?php echo esc_attr($badge_bg); ?>; color:<?php echo esc_attr($badge_color); ?>; font-size:11px; font-weight:700; padding:2px 8px; border-radius:4px;">
                                    <?php echo esc_html($rate); ?>%
                                </span>
                            </td>
                            <td style="text-align:center; font-size:11px; color:#666;"><?php echo esc_html(substr($rep->created_at, 0, 10)); ?></td>
                            <td style="text-align:right;">
                                <button type="button" class="button button-small button-secondary pn-toggle-details-btn" data-target="details-dmarc-<?php echo esc_attr($rep->id); ?>">
                                    👁️ <?php esc_html_e('Details', 'pointnet-mailguard'); ?>
                                </button>
                                <button type="button" class="button button-small button-link-delete pn-delete-report-btn" data-id="<?php echo esc_attr($rep->id); ?>" style="color:#d63638;">
                                    🗑️
                                </button>
                            </td>
                        </tr>
                        <!-- Details Accordion Row -->
                        <tr id="details-dmarc-<?php echo esc_attr($rep->id); ?>" style="display:none; background:#fafafa;">
                            <td colspan="7" style="padding:16px;">
                                <div style="background:#fff; border:1px solid #e0e0e0; border-radius:6px; padding:16px;">
                                    <h4 style="font-size:13px; margin:0 0 10px; color:#1d2327;">🌐 <?php esc_html_e('Sender IPs & Authentication Breakdown', 'pointnet-mailguard'); ?></h4>
                                    <?php if (empty($records)): ?>
                                        <p style="font-size:12px; color:#999; margin:0;"><?php esc_html_e('No sender IP details found.', 'pointnet-mailguard'); ?></p>
                                    <?php else: ?>
                                        <table style="width:100%; border-collapse:collapse; font-size:12px;">
                                            <thead>
                                                <tr style="border-bottom:1.5px solid #e0e0e0; text-align:left; color:#666;">
                                                    <th style="padding:6px;"><?php esc_html_e('Source IP', 'pointnet-mailguard'); ?></th>
                                                    <th style="padding:6px;"><?php esc_html_e('Country', 'pointnet-mailguard'); ?></th>
                                                    <th style="padding:6px; text-align:center;"><?php esc_html_e('Count', 'pointnet-mailguard'); ?></th>
                                                    <th style="padding:6px;"><?php esc_html_e('Disposition', 'pointnet-mailguard'); ?></th>
                                                    <th style="padding:6px; text-align:center;"><?php esc_html_e('SPF Result', 'pointnet-mailguard'); ?></th>
                                                    <th style="padding:6px; text-align:center;"><?php esc_html_e('DKIM Result', 'pointnet-mailguard'); ?></th>
                                                    <th style="padding:6px;"><?php esc_html_e('Header From', 'pointnet-mailguard'); ?></th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($records as $rec):
                                                    $flag = !empty($rec->country_code) ? esc_html($rec->country_code) : '—';
                                                ?>
                                                <tr style="border-bottom:1px solid #eee;">
                                                    <td style="padding:6px; font-family:monospace; font-weight:600;"><?php echo esc_html($rec->source_ip); ?></td>
                                                    <td style="padding:6px; font-weight:600;"><?php echo esc_html($flag); ?></td>
                                                    <td style="padding:6px; text-align:center; font-weight:700;"><?php echo esc_html(number_format_i18n($rec->count)); ?></td>
                                                    <td style="padding:6px;">
                                                        <span style="font-size:10px; text-transform:uppercase; font-weight:600; padding:2px 6px; border-radius:3px; background:#f0f0f1; color:#333;">
                                                            <?php echo esc_html($rec->disposition); ?>
                                                        </span>
                                                    </td>
                                                    <td style="padding:6px; text-align:center;">
                                                        <?php if ($rec->spf_eval === 'pass'): ?>
                                                            <span style="background:#edfaef; color:#00a32a; font-size:10px; font-weight:700; padding:2px 6px; border-radius:3px;">✓ PASS</span>
                                                        <?php else: ?>
                                                            <span style="background:#fbeaea; color:#a30000; font-size:10px; font-weight:700; padding:2px 6px; border-radius:3px;">✗ FAIL</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td style="padding:6px; text-align:center;">
                                                        <?php if ($rec->dkim_eval === 'pass'): ?>
                                                            <span style="background:#edfaef; color:#00a32a; font-size:10px; font-weight:700; padding:2px 6px; border-radius:3px;">✓ PASS</span>
                                                        <?php else: ?>
                                                            <span style="background:#fbeaea; color:#a30000; font-size:10px; font-weight:700; padding:2px 6px; border-radius:3px;">✗ FAIL</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td style="padding:6px; font-size:11px; color:#555;"><?php echo esc_html($rec->header_from); ?></td>
                                                </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <!-- Section 2: TLSRPT Reports -->
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:20px;">
            <h3 style="font-size:15px; margin:0 0 16px; color:#1d2327;">🔒 <?php esc_html_e('TLSRPT Reports (RFC 8460 - MTA-STS / DANE TLS)', 'pointnet-mailguard'); ?></h3>

            <?php if (empty($tls_reports)): ?>
                <p style="font-size:13px; color:#999; text-align:center; padding:20px 0; margin:0;">
                    <?php esc_html_e('No TLSRPT TLS reports imported yet. Upload a .json or .json.gz report file above.', 'pointnet-mailguard'); ?>
                </p>
            <?php else: ?>
                <table class="wp-list-table widefat fixed striped" style="border:none;">
                    <thead>
                        <tr>
                            <th style="width:180px;"><?php esc_html_e('Reporting Org', 'pointnet-mailguard'); ?></th>
                            <th><?php esc_html_e('Policy Domain', 'pointnet-mailguard'); ?></th>
                            <th style="width:180px;"><?php esc_html_e('Date Range', 'pointnet-mailguard'); ?></th>
                            <th style="width:110px; text-align:center;"><?php esc_html_e('Success Sessions', 'pointnet-mailguard'); ?></th>
                            <th style="width:100px; text-align:center;"><?php esc_html_e('Failures', 'pointnet-mailguard'); ?></th>
                            <th style="width:100px; text-align:center;"><?php esc_html_e('Success Rate', 'pointnet-mailguard'); ?></th>
                            <th style="width:130px; text-align:center;"><?php esc_html_e('Imported On', 'pointnet-mailguard'); ?></th>
                            <th style="width:120px; text-align:right;"><?php esc_html_e('Actions', 'pointnet-mailguard'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($tls_reports as $trep):
                            $t_records = $wpdb->get_results($wpdb->prepare("SELECT * FROM %i WHERE report_id_fk = %d", $table_tls_rec, $trep->id));
                        ?>
                        <tr>
                            <td>
                                <strong>🏢 <?php echo esc_html($trep->org_name); ?></strong>
                                <div style="font-size:10px; color:#999; font-family:monospace;"><?php echo esc_html($trep->report_id); ?></div>
                            </td>
                            <td><code><?php echo esc_html($trep->domain); ?></code></td>
                            <td style="font-size:11px; color:#666;">
                                <?php echo esc_html($trep->date_begin ? substr($trep->date_begin, 0, 10) : 'N/A'); ?> → 
                                <?php echo esc_html($trep->date_end ? substr($trep->date_end, 0, 10) : 'N/A'); ?>
                            </td>
                            <td style="text-align:center; font-weight:700; color:#00a32a;">
                                <?php echo esc_html(number_format_i18n($trep->successful_sessions)); ?>
                            </td>
                            <td style="text-align:center; font-weight:700; color:<?php echo esc_attr($trep->failed_sessions > 0 ? '#d63638' : '#666'); ?>;">
                                <?php echo esc_html(number_format_i18n($trep->failed_sessions)); ?>
                            </td>
                            <td style="text-align:center;">
                                <?php
                                $trate = floatval($trep->success_rate);
                                $t_bg = $trate >= 95 ? '#edfaef' : ($trate >= 80 ? '#fff8e5' : '#fbeaea');
                                $t_color = $trate >= 95 ? '#00a32a' : ($trate >= 80 ? '#996800' : '#a30000');
                                ?>
                                <span style="background:<?php echo esc_attr($t_bg); ?>; color:<?php echo esc_attr($t_color); ?>; font-size:11px; font-weight:700; padding:2px 8px; border-radius:4px;">
                                    <?php echo esc_html($trate); ?>%
                                </span>
                            </td>
                            <td style="text-align:center; font-size:11px; color:#666;"><?php echo esc_html(substr($trep->created_at, 0, 10)); ?></td>
                            <td style="text-align:right;">
                                <button type="button" class="button button-small button-secondary pn-toggle-details-btn" data-target="details-tls-<?php echo esc_attr($trep->id); ?>">
                                    👁️ <?php esc_html_e('Details', 'pointnet-mailguard'); ?>
                                </button>
                                <button type="button" class="button button-small button-link-delete pn-delete-tls-report-btn" data-id="<?php echo esc_attr($trep->id); ?>" style="color:#d63638;">
                                    🗑️
                                </button>
                            </td>
                        </tr>
                        <!-- Details Accordion Row for TLS -->
                        <tr id="details-tls-<?php echo esc_attr($trep->id); ?>" style="display:none; background:#fafafa;">
                            <td colspan="8" style="padding:16px;">
                                <div style="background:#fff; border:1px solid #e0e0e0; border-radius:6px; padding:16px;">
                                    <h4 style="font-size:13px; margin:0 0 10px; color:#1d2327;">🔒 <?php esc_html_e('MTA-STS Policies & TLS Session Delivery Breakdown', 'pointnet-mailguard'); ?></h4>
                                    
                                    <?php
                                    $policies_data = json_decode($trep->policies_json ?? '[]', true);
                                    if (!empty($policies_data)):
                                    ?>
                                        <div style="margin-bottom:12px;">
                                            <?php foreach ($policies_data as $p): ?>
                                                <div style="background:#f8f9fa; border:1px solid #e9ecef; border-radius:4px; padding:10px; margin-bottom:8px;">
                                                    <div style="font-size:12px; font-weight:600; color:#1d2327; margin-bottom:4px;">
                                                        Policy Type: <span style="text-transform:uppercase; color:#2271b1;"><?php echo esc_html($p['policy_type'] ?? 'sts'); ?></span>
                                                        | Domain: <code><?php echo esc_html($p['policy_domain'] ?? ''); ?></code>
                                                    </div>
                                                    <?php if (!empty($p['policy_string'])): ?>
                                                        <div style="font-size:11px; color:#555; font-family:monospace; margin-bottom:4px;">
                                                            Strings: <?php echo esc_html(implode(' | ', $p['policy_string'])); ?>
                                                        </div>
                                                    <?php endif; ?>
                                                    <?php if (!empty($p['mx_hosts'])): ?>
                                                        <div style="font-size:11px; color:#555; font-family:monospace;">
                                                            MX Hosts: <?php echo esc_html(implode(', ', $p['mx_hosts'])); ?>
                                                        </div>
                                                    <?php endif; ?>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    <?php endif; ?>

                                    <?php if (!empty($t_records)): ?>
                                        <h5 style="font-size:12px; margin:12px 0 8px; color:#1d2327;"><?php esc_html_e('Failure Details:', 'pointnet-mailguard'); ?></h5>
                                        <table style="width:100%; border-collapse:collapse; font-size:12px;">
                                            <thead>
                                                <tr style="border-bottom:1.5px solid #e0e0e0; text-align:left; color:#666;">
                                                    <th style="padding:6px;"><?php esc_html_e('Result Type', 'pointnet-mailguard'); ?></th>
                                                    <th style="padding:6px;"><?php esc_html_e('Sending MTA IP', 'pointnet-mailguard'); ?></th>
                                                    <th style="padding:6px;"><?php esc_html_e('Receiving IP / MX', 'pointnet-mailguard'); ?></th>
                                                    <th style="padding:6px; text-align:center;"><?php esc_html_e('Failed Count', 'pointnet-mailguard'); ?></th>
                                                    <th style="padding:6px;"><?php esc_html_e('Additional Info', 'pointnet-mailguard'); ?></th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($t_records as $trec):
                                                    $failures = json_decode($trec->failure_details_json ?? '[]', true);
                                                    if (empty($failures)):
                                                ?>
                                                    <tr>
                                                        <td colspan="5" style="padding:6px; color:#00a32a; font-weight:600;">
                                                            ✅ <?php esc_html_e('No TLS failures reported for this policy.', 'pointnet-mailguard'); ?>
                                                        </td>
                                                    </tr>
                                                <?php else:
                                                    foreach ($failures as $f):
                                                ?>
                                                    <tr style="border-bottom:1px solid #eee;">
                                                        <td style="padding:6px; font-weight:700; color:#d63638;"><?php echo esc_html($f['result_type'] ?? 'unknown'); ?></td>
                                                        <td style="padding:6px; font-family:monospace;"><?php echo esc_html($f['sending_mta_ip'] ?? 'N/A'); ?></td>
                                                        <td style="padding:6px; font-family:monospace;">
                                                            <?php echo esc_html($f['receiving_ip'] ?? ''); ?>
                                                            <?php if (!empty($f['receiving_mx_hostname'])): ?>
                                                                (<?php echo esc_html($f['receiving_mx_hostname']); ?>)
                                                            <?php endif; ?>
                                                        </td>
                                                        <td style="padding:6px; text-align:center; font-weight:700; color:#d63638;"><?php echo esc_html(number_format_i18n($f['failed_session_count'] ?? 1)); ?></td>
                                                        <td style="padding:6px; font-size:11px; color:#555;"><?php echo esc_html($f['additional_info'] ?? ''); ?></td>
                                                    </tr>
                                                <?php
                                                    endforeach;
                                                endif;
                                                endforeach;
                                                ?>
                                            </tbody>
                                        </table>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        <?php
    }

    public static function ajax_upload_dmarc_report(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        if (empty($_FILES['dmarc_file']) || $_FILES['dmarc_file']['error'] !== UPLOAD_ERR_OK) {
            wp_send_json_error(['message' => __('No valid file uploaded. Please select an XML, JSON, .gz, or .zip file.', 'pointnet-mailguard')]);
        }

        $tmp_path = $_FILES['dmarc_file']['tmp_name'];
        $raw_bytes = @file_get_contents($tmp_path);
        if ($raw_bytes === false) {
            wp_send_json_error(['message' => __('Unable to read uploaded report file.', 'pointnet-mailguard')]);
        }

        // Check if file is TLSRPT JSON or DMARC XML
        $decompressed = PN_Mailguard_Tlsrpt_Parser::decompress($raw_bytes);
        $is_tlsrpt = false;
        if ($decompressed !== false) {
            $trimmed = ltrim($decompressed);
            if (str_starts_with($trimmed, '{') && (str_contains($trimmed, 'organization-name') || str_contains($trimmed, 'policies'))) {
                $is_tlsrpt = true;
            }
        }

        global $wpdb;

        if ($is_tlsrpt) {
            // Process TLSRPT Report
            $parsed = PN_Mailguard_Tlsrpt_Parser::parse($tmp_path);
            if (!$parsed['success']) {
                wp_send_json_error(['message' => $parsed['error']]);
            }

            $table_tls_rep = $wpdb->prefix . PN_Mailguard_Installer::TABLE_TLS_REPORTS;
            $table_tls_rec = $wpdb->prefix . PN_Mailguard_Installer::TABLE_TLS_RECORDS;

            $meta = $parsed['metadata'];
            $sum  = $parsed['summary'];

            // Duplicate check
            if (!empty($meta['report_id'])) {
                $exists = $wpdb->get_var(
                    $wpdb->prepare("SELECT id FROM %i WHERE report_id = %s AND org_name = %s LIMIT 1", $table_tls_rep, $meta['report_id'], $meta['org_name'])
                );
                if ($exists) {
                    wp_send_json_error(['message' => sprintf(__('TLSRPT Report ID "%s" from %s has already been imported.', 'pointnet-mailguard'), esc_html($meta['report_id']), esc_html($meta['org_name']))]);
                }
            }

            $inserted = $wpdb->insert(
                $table_tls_rep,
                [
                    'report_id'           => $meta['report_id'],
                    'org_name'            => $meta['org_name'],
                    'contact_info'        => $meta['contact_info'],
                    'domain'              => $parsed['domain'],
                    'date_begin'          => $meta['date_begin'] ?: null,
                    'date_end'            => $meta['date_end'] ?: null,
                    'successful_sessions' => $sum['successful_sessions'],
                    'failed_sessions'     => $sum['failed_sessions'],
                    'success_rate'        => $sum['success_rate_percent'],
                    'policies_json'       => wp_json_encode($parsed['policies']),
                    'created_at'          => current_time('mysql'),
                ]
            );

            if (!$inserted) {
                wp_send_json_error(['message' => __('Failed to save TLSRPT report to database.', 'pointnet-mailguard')]);
            }

            $report_db_id = $wpdb->insert_id;

            foreach ($parsed['records'] as $rec) {
                $wpdb->insert(
                    $table_tls_rec,
                    [
                        'report_id_fk'         => $report_db_id,
                        'policy_type'          => $rec['policy_type'],
                        'policy_domain'        => $rec['policy_domain'],
                        'successful_count'     => $rec['successful'],
                        'failed_count'         => $rec['failed'],
                        'failure_details_json' => wp_json_encode($rec['failures']),
                    ]
                );
            }

            wp_send_json_success([
                'message' => sprintf(__('TLSRPT (MTA-STS TLS) Report successfully imported! (%d successful sessions, %d failed).', 'pointnet-mailguard'), $sum['successful_sessions'], $sum['failed_sessions']),
            ]);
        } else {
            // Process DMARC XML Report
            $parsed = PN_Mailguard_Dmarc_Parser::parse($tmp_path);

            if (!$parsed['success']) {
                wp_send_json_error(['message' => $parsed['error']]);
            }

            $table_reports = $wpdb->prefix . PN_Mailguard_Installer::TABLE_DMARC_REPORTS;
            $table_records = $wpdb->prefix . PN_Mailguard_Installer::TABLE_DMARC_RECORDS;

            $meta   = $parsed['metadata'];
            $policy = $parsed['policy_published'];
            $sum    = $parsed['summary'];

            // Check if report_id already exists to prevent duplicate imports
            if (!empty($meta['report_id'])) {
                $exists = $wpdb->get_var(
                    $wpdb->prepare("SELECT id FROM %i WHERE report_id = %s AND org_name = %s LIMIT 1", $table_reports, $meta['report_id'], $meta['org_name'])
                );
                if ($exists) {
                    wp_send_json_error(['message' => sprintf(__('DMARC Report ID "%s" from %s has already been imported.', 'pointnet-mailguard'), esc_html($meta['report_id']), esc_html($meta['org_name']))]);
                }
            }

            // Insert report metadata
            $inserted = $wpdb->insert(
                $table_reports,
                [
                    'report_id'        => $meta['report_id'],
                    'org_name'         => $meta['org_name'],
                    'email'            => $meta['email'],
                    'domain'           => $policy['domain'],
                    'date_begin'       => $meta['date_begin'] ?: null,
                    'date_end'         => $meta['date_end'] ?: null,
                    'total_messages'   => $sum['total_messages'],
                    'passed_messages'  => $sum['passed_messages'],
                    'failed_messages'  => $sum['failed_messages'],
                    'pass_rate'        => $sum['pass_rate_percent'],
                    'policy_published' => wp_json_encode($policy),
                    'created_at'       => current_time('mysql'),
                ]
            );

            if (!$inserted) {
                wp_send_json_error(['message' => __('Failed to save DMARC report to database.', 'pointnet-mailguard')]);
            }

            $report_db_id = $wpdb->insert_id;

            // Insert record items
            foreach ($parsed['records'] as $rec) {
                $wpdb->insert(
                    $table_records,
                    [
                        'report_id_fk'  => $report_db_id,
                        'source_ip'     => $rec['source_ip'],
                        'count'         => $rec['count'],
                        'disposition'   => $rec['disposition'],
                        'dkim_eval'     => $rec['dkim_eval'],
                        'spf_eval'      => $rec['spf_eval'],
                        'header_from'   => $rec['header_from'],
                        'envelope_from' => $rec['envelope_from'],
                        'envelope_to'   => $rec['envelope_to'],
                        'country_code'  => '',
                        'auth_details'  => wp_json_encode([
                            'dkim' => $rec['dkim_results'],
                            'spf'  => $rec['spf_results'],
                        ]),
                    ]
                );
            }

            wp_send_json_success([
                'message' => sprintf(__('DMARC Report successfully imported! (%d messages evaluated, %d passed).', 'pointnet-mailguard'), $sum['total_messages'], $sum['passed_messages']),
            ]);
        }
    }

    public static function ajax_delete_dmarc_report(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $report_id = isset($_POST['report_id']) ? intval($_POST['report_id']) : 0;
        if (!$report_id) {
            wp_send_json_error(['message' => __('Invalid report ID.', 'pointnet-mailguard')]);
        }

        global $wpdb;
        $table_reports = $wpdb->prefix . PN_Mailguard_Installer::TABLE_DMARC_REPORTS;
        $table_records = $wpdb->prefix . PN_Mailguard_Installer::TABLE_DMARC_RECORDS;

        $wpdb->delete($table_records, ['report_id_fk' => $report_id]);
        $wpdb->delete($table_reports, ['id' => $report_id]);

        wp_send_json_success(['message' => __('Report deleted successfully.', 'pointnet-mailguard')]);
    }

    public static function ajax_delete_tls_report(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $report_id = isset($_POST['report_id']) ? intval($_POST['report_id']) : 0;
        if (!$report_id) {
            wp_send_json_error(['message' => __('Invalid report ID.', 'pointnet-mailguard')]);
        }

        global $wpdb;
        $table_reports = $wpdb->prefix . PN_Mailguard_Installer::TABLE_TLS_REPORTS;
        $table_records = $wpdb->prefix . PN_Mailguard_Installer::TABLE_TLS_RECORDS;

        $wpdb->delete($table_records, ['report_id_fk' => $report_id]);
        $wpdb->delete($table_reports, ['id' => $report_id]);

        wp_send_json_success(['message' => __('TLS report deleted successfully.', 'pointnet-mailguard')]);
    }

    public static function ajax_test_imap(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $config = [
            'host'         => sanitize_text_field(wp_unslash($_POST['host'] ?? '')),
            'port'         => intval($_POST['port'] ?? 993),
            'encryption'   => sanitize_text_field(wp_unslash($_POST['encryption'] ?? 'ssl')),
            'username'     => sanitize_text_field(wp_unslash($_POST['username'] ?? '')),
            'password'     => wp_unslash($_POST['password'] ?? ''),
            'mailbox'      => sanitize_text_field(wp_unslash($_POST['mailbox'] ?? 'INBOX')),
            'action_after' => sanitize_text_field(wp_unslash($_POST['action_after'] ?? 'delete')),
        ];

        if (empty($config['password']) || $config['password'] === '********') {
            $config['password'] = PN_Mailguard_Crypto::decrypt(get_option('pn_mailguard_imap_password', ''));
        }

        $res = PN_Mailguard_Imap_Fetcher::test_connection($config);
        if ($res['success']) {
            wp_send_json_success(['message' => $res['message']]);
        } else {
            wp_send_json_error(['message' => $res['message']]);
        }
    }

    public static function ajax_fetch_imap_now(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $res = PN_Mailguard_Imap_Fetcher::fetch_reports();
        if ($res['success']) {
            wp_send_json_success([
                'message'        => $res['message'],
                'imported'       => $res['imported'],
                'duplicates'     => $res['duplicates'],
                'failed'         => $res['failed'],
                'imported_list'  => $res['imported_list'] ?? [],
                'duplicates_list'=> $res['duplicates_list'] ?? [],
                'errors'         => $res['errors'] ?? [],
            ]);
        } else {
            wp_send_json_error(['message' => $res['message']]);
        }
    }

    public static function ajax_reset_dmarc_data(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        global $wpdb;
        $table_records = $wpdb->prefix . PN_Mailguard_Installer::TABLE_DMARC_RECORDS;
        $table_reports = $wpdb->prefix . PN_Mailguard_Installer::TABLE_DMARC_REPORTS;
        $table_tls_rec = $wpdb->prefix . PN_Mailguard_Installer::TABLE_TLS_RECORDS;
        $table_tls_rep = $wpdb->prefix . PN_Mailguard_Installer::TABLE_TLS_REPORTS;

        $wpdb->query("TRUNCATE TABLE `{$table_records}`");
        $wpdb->query("TRUNCATE TABLE `{$table_reports}`");
        $wpdb->query("TRUNCATE TABLE `{$table_tls_rec}`");
        $wpdb->query("TRUNCATE TABLE `{$table_tls_rep}`");

        delete_option('pn_mailguard_imap_last_fetch_time');
        delete_option('pn_mailguard_imap_last_fetch_summary');

        wp_send_json_success(['message' => __('All DMARC and TLSRPT database records and fetch history have been successfully cleared.', 'pointnet-mailguard')]);
    }
}
