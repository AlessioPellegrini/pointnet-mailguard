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
        register_setting('pn_mailguard_settings', 'pn_mailguard_uninstall_cleanup', ['sanitize_callback' => 'sanitize_text_field']);
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

        // Save DKIM selector and Gemini config (from onboarding or advanced tab)
        $dkim_selector = isset($_POST['pn_mailguard_dkim_selector']) ? sanitize_text_field(wp_unslash($_POST['pn_mailguard_dkim_selector'])) : '';
        $gemini_model  = isset($_POST['pn_mailguard_gemini_model']) ? sanitize_text_field(wp_unslash($_POST['pn_mailguard_gemini_model'])) : '';
        update_option('pn_mailguard_dkim_selector', $dkim_selector);

        // Encrypt Gemini API key before storing in the database.
        // The HTML password field shows "********" as placeholder when a key is already saved.
        // If the submitted value is empty or the placeholder, keep the existing encrypted key.
        $submitted_key = isset($_POST['pn_mailguard_gemini_key']) ? sanitize_text_field(wp_unslash($_POST['pn_mailguard_gemini_key'])) : '';

        if (empty($submitted_key)) {
            // User cleared the field — delete the key
            delete_option('pn_mailguard_gemini_key');
        } elseif ($submitted_key === '********') {
            // User did not change the key — preserve whatever is stored
            // (no update needed, the existing value remains)
        } else {
            // User entered a new key — encrypt and save it
            $gemini_key = PN_Mailguard_Crypto::encrypt($submitted_key);
            update_option('pn_mailguard_gemini_key', $gemini_key);
        }
        update_option('pn_mailguard_gemini_model', $gemini_model);

        // Save uninstall cleanup preference
        // Only update when the field is present in the request (Advanced tab).
        // Other tabs (Monitors, Onboarding) do not include this field, so the existing value is preserved.
        if (array_key_exists('pn_mailguard_uninstall_cleanup', $_POST)) {
            update_option('pn_mailguard_uninstall_cleanup', $_POST['pn_mailguard_uninstall_cleanup'] === '1' ? '1' : '0');
        }

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

        $tabs   = ['monitors', 'customip', 'dnstools', 'advanced', 'support'];
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
                    'monitors'  => '📊 ' . __('Monitors',    'pointnet-mailguard'),
                    'customip'  => '🌐 ' . __('Custom IP',   'pointnet-mailguard'),
                    'dnstools'  => '🔬 ' . __('DNS & IP Tools',   'pointnet-mailguard'),
                    'advanced'  => '⚙️ '  . __('Advanced',    'pointnet-mailguard'),
                    'support'   => '📤 '  . __('Export / Support', 'pointnet-mailguard'),
                ];
                foreach ($tab_labels as $key => $label) {
                    $active = $tab === $key ? 'nav-tab-active' : '';
                    echo '<a href="' . esc_url($base . '&tab=' . $key) . '" class="nav-tab ' . esc_attr($active) . '">' . esc_html($label) . '</a>';
                }
                ?>
            </nav>

            <?php
            switch ($tab) {
                case 'monitors': self::render_monitors($check_email, $check_ip); break;
                case 'customip': self::render_custom_ip($check_ip); break;
                case 'dnstools': self::render_dnstools(); break;
                case 'advanced': self::render_advanced(); break;
                case 'support':  self::render_support(); break;
            }
            ?>
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
            <p style="font-size:13px; color:#50575e; margin:0 0 16px;">
                <?php esc_html_e('Set up your first monitor in just 2 minutes. Follow the steps below:', 'pointnet-mailguard'); ?>
            </p>

            <form method="post" style="display:grid; grid-template-columns:repeat(auto-fit, minmax(240px,1fr)); gap:16px;">
                <?php wp_nonce_field('pn_mailguard_save_action', 'pn_mailguard_nonce'); ?>
                <div style="background:#fff; border-radius:8px; padding:16px; border:1px solid #dcdcde;">
                    <div style="font-size:24px; margin-bottom:8px;">📧</div>
                    <p style="font-weight:600; margin:0 0 4px;"><?php esc_html_e('Step 1: Email to monitor', 'pointnet-mailguard'); ?></p>
                    <p style="font-size:12px; color:#666; margin:0 0 10px;">
                        <?php esc_html_e('The email address you send from — we will detect your mail server IP automatically via MX lookup.', 'pointnet-mailguard'); ?>
                    </p>
                    <input type="email" id="onboarding-email" name="pn_mailguard_check_email" value="" class="regular-text" placeholder="info@yourdomain.com" style="width:100%;">
                </div>

                <div style="background:#fff; border-radius:8px; padding:16px; border:1px solid #dcdcde;">
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

                <div style="background:#fff; border-radius:8px; padding:16px; border:1px solid #dcdcde;">
                    <div style="font-size:24px; margin-bottom:8px;">📬</div>
                    <p style="font-weight:600; margin:0 0 4px;"><?php esc_html_e('Step 3: Alert email', 'pointnet-mailguard'); ?></p>
                    <p style="font-size:12px; color:#666; margin:0 0 10px;">
                        <?php esc_html_e('Where to receive alerts when problems are detected.', 'pointnet-mailguard'); ?>
                    </p>
                    <input type="email" name="pn_mailguard_email_alert" id="onboarding-alert-email" value="<?php echo esc_attr(get_option('admin_email')); ?>" class="regular-text" style="width:100%;">
                    <p style="font-size:11px; color:#dba617; margin:6px 0 0; background:#fff8e5; padding:6px 8px; border-radius:3px;">
                        💡 <?php esc_html_e('Tip: use a different email from the one you monitor. If your mail server has issues, alerts sent to the same monitored address may not arrive.', 'pointnet-mailguard'); ?>
                    </p>
                </div>

                <div style="background:#fff; border-radius:8px; padding:16px; border:1px solid #dcdcde;">
                    <div style="font-size:24px; margin-bottom:8px;">🔑</div>
                    <p style="font-weight:600; margin:0 0 4px;"><?php esc_html_e('Step 4: DKIM Selector (optional)', 'pointnet-mailguard'); ?></p>
                    <p style="font-size:12px; color:#666; margin:0 0 10px;">
                        <?php esc_html_e('If known, enter your DKIM selector. Leave empty to auto-detect.', 'pointnet-mailguard'); ?>
                    </p>
                    <div style="display:flex; gap:6px;">
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

                <div style="grid-column:1/-1;">
                    <input type="submit" name="pn_mailguard_save_settings" class="button button-primary button-hero" value="<?php esc_attr_e('Save & Start Monitoring →', 'pointnet-mailguard'); ?>" style="width:100%;">
                </div>
            </form>
        </div>

        <script>
        // Auto-fill alert email from monitored email step
        document.getElementById('onboarding-email').addEventListener('input', function() {
            var alertField = document.getElementById('onboarding-alert-email');
            if (alertField && !alertField._userEdited) {
                alertField.value = this.value;
            }
        });
        document.getElementById('onboarding-alert-email').addEventListener('input', function() {
            this._userEdited = true;
        });
        </script>

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

        $spf_data   = $domain ? PN_Mailguard_SPF::analyze($domain) : null;
        $dmarc_data = $domain ? PN_Mailguard_DMARC::analyze($domain) : null;
        $dkim_sel   = get_option('pn_mailguard_dkim_selector', '');
        $dkim_data  = ($domain && $dkim_sel) ? PN_Mailguard_DKIM::analyze($domain, $dkim_sel) : null;

        $last_email = self::get_last_log('email');
        $last_ip    = self::get_last_log('ip');

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
        if ($spf_data   && $spf_data['status']  !== 'ok') $issues++;
        if ($dmarc_data  && $dmarc_data['status'] !== 'ok') $issues++;
        if ($dkim_data   && $dkim_data['status']  !== 'ok') $issues++;
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
                    <?php self::badge('SPF',   $spf_data,   'spf'); ?>
                    <?php self::badge('DMARC', $dmarc_data, 'dmarc'); ?>
                    <?php self::badge('DKIM',  $dkim_data,  'dkim'); ?>
                    <?php self::monitor_badge(__('Email', 'pointnet-mailguard'), $last_email, !empty($check_email) && is_email($check_email)); ?>
                    <?php self::monitor_badge(__('IP',    'pointnet-mailguard'), $last_ip, !empty($check_ip) && filter_var($check_ip, FILTER_VALIDATE_IP)); ?>
                </div>
            </div>
        </div>

        <!-- Email Monitor card (full width, standalone) -->
        <div style="margin-bottom:24px;">
            <?php self::monitor_card_v2('email', $check_email, $last_email, $domain); ?>
        </div>

        <!-- DNS Record Status -->
        <?php if ($domain): ?>
        <h2 style="font-size:15px; margin:0 0 12px; color:#50575e;">🔐 <?php esc_html_e('DNS Record Status', 'pointnet-mailguard'); ?></h2>
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px,1fr)); gap:16px; margin-bottom:24px;">
            <?php self::render_analyzer_section('spf',   '🔐', 'SPF',   $spf_data, $domain); ?>
            <?php self::render_analyzer_section('dmarc', '📋', 'DMARC', $dmarc_data, $domain); ?>
            <?php self::render_analyzer_section('dkim',  '🔑', 'DKIM',  $dkim_data, $domain); ?>
        </div>
        <?php endif; ?>

        <!-- DNSBL check results -->
        <?php if (!empty($dnsbl_results)): ?>
        <h2 style="font-size:15px; margin:0 0 12px; color:#50575e;">🚫 <?php esc_html_e('DNSBL Blacklist Check', 'pointnet-mailguard'); ?></h2>
        <div style="display:flex; flex-wrap:wrap; gap:8px; margin-bottom:24px;">
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
        <?php endif; ?>

        <!-- Recent scans compact (email only) -->
        <h2 style="font-size:15px; margin:0 0 12px; color:#50575e;">📋 <?php esc_html_e('Recent scans', 'pointnet-mailguard'); ?></h2>
        <div style="margin-bottom:24px;">
            <?php self::monitor_card('email', __('Email Monitor', 'pointnet-mailguard'), '📧'); ?>
        </div>

        <?php self::render_dashboard_js(); ?>
        <?php
    }

    private static function badge(string $label, $data, string $type = ''): void {
        $base_url = admin_url('admin.php?page=pn-mailguard&tab=dnstools');
        if (!$data) {
            echo '<a href="' . esc_url($base_url) . '" style="text-decoration:none;"><span style="background:#f0f0f0; color:#999; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px; cursor:pointer;">' . esc_html($label) . ' —</span></a>';
            return;
        }
        $status_class = match ($data['status']) {
            'ok'             => 'passed',
            'error', 'missing' => 'error',
            default            => 'warning',
        };
        if ($status_class === 'passed') {
            echo '<span style="background:#edfaef; color:#00a32a; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px;">✓ ' . esc_html($label) . '</span>';
        } elseif ($status_class === 'error') {
            echo '<a href="' . esc_url($base_url) . '" style="text-decoration:none;"><span style="background:#fbeaea; color:#a30000; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px; cursor:pointer;">✗ ' . esc_html($label) . '</span></a>';
        } else {
            echo '<a href="' . esc_url($base_url) . '" style="text-decoration:none;"><span style="background:#fff8e5; color:#996800; font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px; cursor:pointer;">⚠ ' . esc_html($label) . '</span></a>';
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
                    <label style="font-size:11px; font-weight:600; display:block; margin-bottom:2px;">📬 <?php esc_html_e('Alert email', 'pointnet-mailguard'); ?></label>
                    <input type="email" class="pn-edit-alert" value="<?php echo esc_attr(get_option('pn_mailguard_email_alert', '')); ?>" placeholder="admin@yourdomain.com" style="width:100%; padding:6px 8px; font-size:12px; margin-bottom:10px;">
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
            <?php self::monitor_card('ip', __('Custom IP Monitor', 'pointnet-mailguard'), '🌐'); ?>
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

    private static function monitor_card(string $type, string $label, string $icon): void {
        global $wpdb;
        $table = $wpdb->prefix . ($type === 'ip' ? PN_Mailguard_Installer::TABLE_IP : PN_Mailguard_Installer::TABLE_EMAIL);
        $logs  = $wpdb->get_results($wpdb->prepare("SELECT * FROM %i ORDER BY scan_date DESC LIMIT %d", $table, 5));
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px;">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">
                <span style="font-size:14px; font-weight:600;"><?php echo esc_html($icon . ' ' . $label); ?></span>
                <span style="font-size:11px; color:#999;">
                    <?php esc_html_e('Last 5 scans', 'pointnet-mailguard'); ?>
                </span>
            </div>
            <?php if ($logs): ?>
                <?php foreach ($logs as $log): ?>
                    <?php $color = PN_Mailguard_Logger::status_color($log->status); ?>
                    <div style="display:flex; align-items:center; gap:8px; padding:6px 0; border-bottom:0.5px solid #f0f0f0;">
                        <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:<?php echo esc_attr($color); ?>; flex-shrink:0;"></span>
                        <span style="font-size:12px; color:#666; flex:1;"><?php echo esc_html($log->scan_date); ?></span>
                        <span style="font-size:12px; font-weight:600; color:<?php echo esc_attr($color); ?>;"><?php echo esc_html($log->status); ?></span>
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
                    <label style="font-size:11px; font-weight:600; display:block; margin-bottom:2px;">📧 <?php esc_html_e('Email', 'pointnet-mailguard'); ?></label>
                    <input type="email" class="pn-edit-email" value="<?php echo esc_attr($value); ?>" placeholder="info@yourdomain.com" style="width:100%; padding:6px 8px; font-size:12px; margin-bottom:8px;">
                    <?php else: ?>
                    <label style="font-size:11px; font-weight:600; display:block; margin-bottom:2px;">🌐 <?php esc_html_e('IP Address', 'pointnet-mailguard'); ?></label>
                    <input type="text" class="pn-edit-ip" value="<?php echo esc_attr($value); ?>" placeholder="1.2.3.4" style="width:100%; padding:6px 8px; font-size:12px; margin-bottom:8px;">
                    <?php endif; ?>
                    <label style="font-size:11px; font-weight:600; display:block; margin-bottom:2px;">📬 <?php esc_html_e('Alert email', 'pointnet-mailguard'); ?></label>
                    <input type="email" class="pn-edit-alert" value="<?php echo esc_attr($alert_email); ?>" placeholder="admin@yourdomain.com" style="width:100%; padding:6px 8px; font-size:12px; margin-bottom:10px;">
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

    private static function render_analyzer_section(string $type, string $icon, string $label, $data, string $domain): void {
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; overflow:hidden;">
            <div style="background:#f8f8f8; border-bottom:1px solid #e0e0e0; padding:12px 16px; display:flex; align-items:center; justify-content:space-between;">
                <span style="font-size:14px; font-weight:600;">
                    <span style="font-size:18px;"><?php echo esc_html($icon); ?></span>
                    <?php echo esc_html($label . ' Analyzer'); ?>
                </span>
                <span style="font-size:11px; color:#999;">
                    <?php esc_html_e('Last scan', 'pointnet-mailguard'); ?>
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
                    <table style="width:100%; border-collapse:collapse; font-size:12px;">
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
                            <td style="padding:6px 4px; color:#555; line-height:1.4;"><?php echo esc_html($c['description']); ?></td>
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

    private static function render_dashboard_js(): void {
        ?>
        <script>
        jQuery(document).ready(function($) {
            var pnNonce = "<?php echo esc_js(wp_create_nonce('pn_mailguard_ajax_nonce')); ?>";

            $('#pn-run-scheduled-btn').on('click', function() {
                var btn = $(this);
                btn.prop('disabled', true).text('⏳ <?php echo esc_js(__('Running...', 'pointnet-mailguard')); ?>');
                $.post(ajaxurl, { action: 'pn_mailguard_run_scheduled', nonce: pnNonce }, function(res) {
                    if (res.success) {
                        location.reload();
                    } else {
                        alert(res.data && res.data.message ? res.data.message : '<?php echo esc_js(__('Scan failed.', 'pointnet-mailguard')); ?>');
                        btn.prop('disabled', false).text('▶️ <?php echo esc_js(__('Run Scheduled Scan Now', 'pointnet-mailguard')); ?>');
                    }
                });
            });

        });
        </script>
        <?php
    }

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
                self::render_dns_section('spf',   '🔐', 'SPF',   $nonce, $dns_domain);
                self::render_dns_section('dmarc', '📋', 'DMARC', $nonce, $dns_domain);
                self::render_dns_section('dkim',  '🔑', 'DKIM',  $nonce, $dns_domain);
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

        <?php self::render_dnstools_js(); ?>
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

    private static function render_dnstools_js(): void {
        ?>
        <script>
        jQuery(document).ready(function($) {
            var pnNonce = "<?php echo esc_js(wp_create_nonce('pn_mailguard_ajax_nonce')); ?>";
            var isAnalyzing = false;

            var $domainInput = $('#pn-dns-domain');
            var autoDomain = $domainInput.data('auto');
            if (autoDomain && !$domainInput.val()) {
                $domainInput.val(autoDomain);
            }

            function getDomain() {
                return $domainInput.val().trim();
            }

            function getSelector() {
                return $('#pn-dns-dkim-selector').val().trim();
            }

            function analyzeAll() {
                var domain = getDomain();
                if (!domain) return;

                isAnalyzing = true;
                $('#pn-dns-analyze-all').prop('disabled', true).text('⏳ <?php echo esc_js(__('Analyzing...', 'pointnet-mailguard')); ?>');

                $('#pn-dkim-selector-row').slideDown();

                runSingle('spf', domain, null, function() {
                    runSingle('dmarc', domain, null, function() {
                        runSingle('dkim', domain, getSelector(), function() {
                            isAnalyzing = false;
                            $('#pn-dns-analyze-all').prop('disabled', false).text('🔬 <?php echo esc_js(__('Analyze All Records', 'pointnet-mailguard')); ?>');
                        });
                    });
                });
            }

            function runSingle(type, domain, selector, callback) {
                var action = type === 'spf' ? 'pn_mailguard_analyze_spf'
                          : type === 'dmarc' ? 'pn_mailguard_analyze_dmarc'
                          : 'pn_mailguard_analyze_dkim';

                var $body = $('#pn-dns-' + type + '-body');
                $body.html('<p style="color:#999;">⏳ <?php echo esc_js(__('Analyzing...', 'pointnet-mailguard')); ?></p>');

                var data = { action: action, nonce: pnNonce, domain: domain };
                if (type === 'dkim' && selector) {
                    data.selector = selector;
                }

                $.post(ajaxurl, data, function(res) {
                    if (!res.success) {
                        var msg = (res.data && res.data.message) ? res.data.message : '<?php echo esc_js(__('Analysis failed.', 'pointnet-mailguard')); ?>';
                        $body.html('<div class="notice notice-error inline" style="margin:0;"><p>' + msg + '</p></div>');
                        if (callback) callback();
                        return;
                    }

                    var d = res.data;

                    if (d.autodetected && d.selector) {
                        $('#pn-dns-dkim-selector').val(d.selector);
                    }

                    var html = '';

                    if (d.record) {
                        html += '<div style="background:#1e1e2e; color:#a6e3a1; font-family:monospace; font-size:11px; padding:8px 10px; border-radius:4px; word-break:break-all; margin-bottom:12px; line-height:1.5;">' + escHtml(d.record) + '</div>';
                    }

                    if (d.passed !== undefined) {
                        html += '<div style="display:grid; grid-template-columns:repeat(3,1fr); gap:6px; margin-bottom:12px;">';
                        html += dnsCard(d.passed,   '<?php echo esc_js(__('passed', 'pointnet-mailguard')); ?>',   '#00a32a');
                        html += dnsCard(d.warnings, '<?php echo esc_js(__('warnings', 'pointnet-mailguard')); ?>', '#dba617');
                        html += dnsCard(d.errors,   '<?php echo esc_js(__('errors', 'pointnet-mailguard')); ?>',   '#d63638');
                        html += '</div>';
                    }

                    if (d.checks && d.checks.length) {
                        html += '<table style="width:100%; border-collapse:collapse; font-size:12px;">';
                        $.each(d.checks, function(i, c) {
                            var dotColor = c.status === 'ok' ? '#00a32a' : (c.status === 'warning' ? '#dba617' : (c.status === 'info' ? '#2271b1' : '#d63638'));
                            var badgeText = c.status === 'ok' ? '✓ Pass' : (c.status === 'warning' ? '⚠ Warning' : (c.status === 'info' ? 'ℹ Info' : '✗ Error'));
                            var badgeBg = c.status === 'ok' ? '#edfaef' : (c.status === 'warning' ? '#fff8e5' : (c.status === 'info' ? '#e8f0fb' : '#fbeaea'));
                            var badgeColor = c.status === 'ok' ? '#00a32a' : (c.status === 'warning' ? '#996800' : (c.status === 'info' ? '#2271b1' : '#a30000'));
                            var bg = i % 2 === 0 ? '#fff' : '#fafafa';
                            html += '<tr style="background:' + bg + '; border-top:0.5px solid #e8e8e8;">';
                            html += '<td style="padding:6px 4px 6px 8px; width:10px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + dotColor + ';"></span></td>';
                            html += '<td style="padding:6px 4px; font-weight:600; width:40%;">' + escHtml(c.title) + '</td>';
                            html += '<td style="padding:6px 4px; width:70px;"><span style="background:' + badgeBg + ';color:' + badgeColor + ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;">' + badgeText + '</span></td>';
                            html += '<td style="padding:6px 4px; color:#555; line-height:1.4;">' + escHtml(c.description) + '</td>';
                            html += '</tr>';
                        });
                        html += '</table>';
                    }

                    if (d.providers && d.providers.length) {
                        html += '<p style="font-size:11px; color:#666; margin:8px 0 0;"><?php echo esc_js(__('Detected providers:', 'pointnet-mailguard')); ?> ' + d.providers.join(', ') + '</p>';
                    }

                    $body.html(html);
                    if (callback) callback();
                });
            }

            function escHtml(str) { return $('<div>').text(str).html(); }

            function dnsCard(num, label, color) {
                return '<div style="background:#f8f8f8;border-radius:4px;padding:8px;text-align:center;border:1px solid #e0e0e0;">'
                    + '<div style="font-size:18px;font-weight:600;color:' + color + ';">' + num + '</div>'
                    + '<div style="font-size:10px;color:#666;margin-top:2px;">' + label + '</div></div>';
            }

            $('#pn-dns-analyze-all').on('click', analyzeAll);

            $('.pn-dns-single-btn').on('click', function() {
                var type = $(this).data('type');
                var domain = getDomain();
                if (!domain) return;
                if (type === 'dkim') {
                    $('#pn-dkim-selector-row').slideDown();
                }
                runSingle(type, domain, type === 'dkim' ? getSelector() : null, null);
            });

            $('#pn-dns-domain').on('keydown', function(e) {
                if (e.key === 'Enter' && !isAnalyzing) {
                    e.preventDefault();
                    analyzeAll();
                }
            });

            // --- IP Analysis ---
            var isIpAnalyzing = false;

            function getIp() {
                return $('#pn-ip-address').val().trim();
            }

            function analyzeIpAll() {
                var ip = getIp();
                if (!ip) return;

                isIpAnalyzing = true;
                $('#pn-ip-analyze-all').prop('disabled', true).text('⏳ <?php echo esc_js(__('Analyzing...', 'pointnet-mailguard')); ?>');

                runIpSingle('dnsbl', ip, function() {
                    runIpSingle('ptr', ip, function() {
                        runIpSingle('geoip', ip, function() {
                            runIpSingle('whois', ip, function() {
                                isIpAnalyzing = false;
                                $('#pn-ip-analyze-all').prop('disabled', false).text('🔬 <?php echo esc_js(__('Analyze IP', 'pointnet-mailguard')); ?>');
                            });
                        });
                    });
                });
            }

            function runIpSingle(type, ip, callback) {
                var action = type === 'dnsbl' ? 'pn_mailguard_ip_dnsbl'
                          : type === 'ptr' ? 'pn_mailguard_ip_ptr'
                          : type === 'geoip' ? 'pn_mailguard_ip_geoip'
                          : 'pn_mailguard_ip_whois';

                var $body = $('#pn-ip-' + type + '-body');
                $body.html('<p style="color:#999;">⏳ <?php echo esc_js(__('Analyzing...', 'pointnet-mailguard')); ?></p>');

                $.post(ajaxurl, { action: action, nonce: pnNonce, ip: ip }, function(res) {
                    if (!res.success) {
                        var msg = (res.data && res.data.message) ? res.data.message : '<?php echo esc_js(__('Analysis failed.', 'pointnet-mailguard')); ?>';
                        $body.html('<div class="notice notice-error inline" style="margin:0;"><p>' + msg + '</p></div>');
                        if (callback) callback();
                        return;
                    }

                    var d = res.data;
                    var html = '';

                    if (type === 'dnsbl') {
                        if (d.results) {
                            var anyListed = false;
                            var ipv6Notice = false;
                            html += '<table style="width:100%; border-collapse:collapse; font-size:12px;">';
                            $.each(d.results, function(name, status) {
                                if (name.indexOf('ℹ️') === 0) {
                                    // Informational message (e.g. IPv6 notice) — show as blue info
                                    ipv6Notice = true;
                                    html += '<tr style="border-top:0.5px solid #e8e8e8;">';
                                    html += '<td style="padding:6px 4px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#2271b1;"></span></td>';
                                    html += '<td style="padding:6px 4px; font-weight:600; color:#2271b1;">' + escHtml(name) + '</td>';
                                    html += '<td style="padding:6px 4px; color:#2271b1; font-size:11px;">' + escHtml(status) + '</td>';
                                    html += '</tr>';
                                } else {
                                    if (status === 'LISTED') anyListed = true;
                                    var dotColor = status === 'LISTED' ? '#d63638' : '#00a32a';
                                    var badgeText = status === 'LISTED' ? '✗ LISTED' : '✓ CLEAN';
                                    var badgeBg = status === 'LISTED' ? '#fbeaea' : '#edfaef';
                                    var badgeColor = status === 'LISTED' ? '#a30000' : '#00a32a';
                                    html += '<tr style="border-top:0.5px solid #e8e8e8;">';
                                    html += '<td style="padding:6px 4px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + dotColor + ';"></span></td>';
                                    html += '<td style="padding:6px 4px; font-weight:600;">' + escHtml(name) + '</td>';
                                    html += '<td style="padding:6px 4px;"><span style="background:' + badgeBg + ';color:' + badgeColor + ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;">' + badgeText + '</span></td>';
                                    html += '</tr>';
                                }
                            });
                            html += '</table>';
                            if (anyListed) {
                                html += '<p style="font-size:11px; color:#d63638; margin:8px 0 0;">⚠ <?php echo esc_js(__('IP is listed on one or more blacklists!', 'pointnet-mailguard')); ?></p>';
                            } else if (!ipv6Notice) {
                                html += '<p style="font-size:11px; color:#00a32a; margin:8px 0 0;">✅ <?php echo esc_js(__('IP is clean on all checked blacklists.', 'pointnet-mailguard')); ?></p>';
                            }
                        } else {
                            html = '<p style="font-size:13px; color:#999; margin:0;"><?php echo esc_js(__('No DNSBL results.', 'pointnet-mailguard')); ?></p>';
                        }
                    } else if (type === 'ptr') {
                        if (d.ptr_warning) {
                            html = '<div style="background:#fff8e5; border:1px solid #f0d080; border-radius:4px; padding:10px; font-size:12px;">';
                            html += '<strong style="color:#996800;">⚠ <?php echo esc_js(__('No PTR record found', 'pointnet-mailguard')); ?></strong>';
                            html += '<p style="margin:4px 0 0; color:#666;"><?php echo esc_js(__('PTR: ', 'pointnet-mailguard')); ?>' + escHtml(d.ptr) + '</p>';
                            html += '</div>';
                        } else {
                            html = '<div style="background:#1e1e2e; color:#a6e3a1; font-family:monospace; font-size:11px; padding:8px 10px; border-radius:4px; word-break:break-all; line-height:1.5;">' + escHtml(d.ptr) + '</div>';
                            html += '<p style="font-size:11px; color:#00a32a; margin:6px 0 0;">✅ <?php echo esc_js(__('PTR record found', 'pointnet-mailguard')); ?></p>';
                        }
                    } else if (type === 'geoip') {
                        if (d.status === 'success') {
                            html += '<table style="width:100%; border-collapse:collapse; font-size:12px;">';
                            var fields = [
                                ['<?php echo esc_js(__('IP', 'pointnet-mailguard')); ?>', d.ip],
                                ['<?php echo esc_js(__('Country', 'pointnet-mailguard')); ?>', d.country + ' (' + d.countryCode + ')'],
                                ['<?php echo esc_js(__('Region', 'pointnet-mailguard')); ?>', d.region],
                                ['<?php echo esc_js(__('City', 'pointnet-mailguard')); ?>', d.city],
                                ['<?php echo esc_js(__('ISP', 'pointnet-mailguard')); ?>', d.isp],
                                ['<?php echo esc_js(__('Organization', 'pointnet-mailguard')); ?>', d.org],
                                ['<?php echo esc_js(__('ASN', 'pointnet-mailguard')); ?>', d.as],
                            ];
                            $.each(fields, function(i, f) {
                                if (f[1]) {
                                    html += '<tr style="border-top:0.5px solid #e8e8e8;">';
                                    html += '<td style="padding:4px 6px; font-weight:600; width:30%;">' + escHtml(f[0]) + '</td>';
                                    html += '<td style="padding:4px 6px; color:#333;">' + escHtml(f[1]) + '</td>';
                                    html += '</tr>';
                                }
                            });
                            html += '</table>';
                        } else {
                            html = '<p style="font-size:13px; color:#d63638; margin:0;">' + escHtml(d.error) + '</p>';
                        }
                    } else if (type === 'whois') {
                        if (d.status === 'success') {
                            html += '<table style="width:100%; border-collapse:collapse; font-size:12px;">';
                            var fields = [
                                ['<?php echo esc_js(__('IP Range', 'pointnet-mailguard')); ?>', d.inetnum],
                                ['<?php echo esc_js(__('Net Name', 'pointnet-mailguard')); ?>', d.netname],
                                ['<?php echo esc_js(__('Organization', 'pointnet-mailguard')); ?>', d.org],
                                ['<?php echo esc_js(__('Country', 'pointnet-mailguard')); ?>', d.country],
                                ['<?php echo esc_js(__('Person', 'pointnet-mailguard')); ?>', d.person],
                                ['<?php echo esc_js(__('Email', 'pointnet-mailguard')); ?>', d.email],
                                ['<?php echo esc_js(__('Source', 'pointnet-mailguard')); ?>', d.source],
                            ];
                            $.each(fields, function(i, f) {
                                if (f[1]) {
                                    html += '<tr style="border-top:0.5px solid #e8e8e8;">';
                                    html += '<td style="padding:4px 6px; font-weight:600; width:35%;">' + escHtml(f[0]) + '</td>';
                                    html += '<td style="padding:4px 6px; color:#333;">' + escHtml(f[1]) + '</td>';
                                    html += '</tr>';
                                }
                            });
                            html += '</table>';
                            if (d.remarks) {
                                html += '<p style="font-size:11px; color:#666; margin:6px 0 0;">' + escHtml(d.remarks) + '</p>';
                            }
                        } else {
                            html = '<p style="font-size:13px; color:#d63638; margin:0;">' + escHtml(d.error) + '</p>';
                        }
                    }

                    $body.html(html);
                    if (callback) callback();
                }).fail(function() {
                    $body.html('<div class="notice notice-error inline" style="margin:0;"><p><?php echo esc_js(__('Network error.', 'pointnet-mailguard')); ?></p></div>');
                    if (callback) callback();
                });
            }

            $('#pn-ip-analyze-all').on('click', analyzeIpAll);
            $('#pn-ip-address').on('keydown', function(e) {
                if (e.key === 'Enter' && !isIpAnalyzing) {
                    e.preventDefault();
                    analyzeIpAll();
                }
            });
        });
        </script>
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

        <script>
        jQuery(document).ready(function($) {
            var pnNonce = "<?php echo esc_js(wp_create_nonce('pn_mailguard_ajax_nonce')); ?>";
            var $fetchBtn = $('#pn-fetch-models-btn');
            var $modelSelect = $('#pn_mailguard_gemini_model');
            var $fetchStatus = $('#pn-fetch-models-status');

            $fetchBtn.on('click', function() {
                $fetchBtn.prop('disabled', true).text('⏳ <?php echo esc_js(__('Loading...', 'pointnet-mailguard')); ?>');
                $fetchStatus.html('<span style="color:#999;"><?php echo esc_js(__('Fetching available models...', 'pointnet-mailguard')); ?></span>');

                $.post(ajaxurl, {
                    action: 'pn_mailguard_fetch_models',
                    nonce: pnNonce
                }, function(res) {
                    $fetchBtn.prop('disabled', false).text('🔄 <?php echo esc_js(__('Fetch Models', 'pointnet-mailguard')); ?>');
                    if (res.success && res.data) {
                        var currentVal = $modelSelect.val();
                        $modelSelect.find('option:not(:first)').remove();
                        var hasModels = false;
                        $.each(res.data, function(id, display) {
                            var selected = (id === currentVal) ? ' selected' : '';
                            $modelSelect.append('<option value="' + id + '"' + selected + '>' + display + ' (' + id + ')</option>');
                            hasModels = true;
                        });
                        if (hasModels) {
                            $fetchStatus.html('<span style="color:#00a32a;">✅ <?php echo esc_js(__('Models updated successfully.', 'pointnet-mailguard')); ?></span>');
                        } else {
                            $fetchStatus.html('<span style="color:#dba617;"><?php echo esc_js(__('No models found. Make sure your API key is valid.', 'pointnet-mailguard')); ?></span>');
                        }
                    } else {
                        $fetchStatus.html('<span style="color:#d63638;"><?php echo esc_js(__('Failed to fetch models. Check your API key.', 'pointnet-mailguard')); ?></span>');
                    }
                }).fail(function() {
                    $fetchBtn.prop('disabled', false).text('🔄 <?php echo esc_js(__('Fetch Models', 'pointnet-mailguard')); ?>');
                    $fetchStatus.html('<span style="color:#d63638;"><?php echo esc_js(__('Network error.', 'pointnet-mailguard')); ?></span>');
                });
            });
        });
        </script>
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
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px;">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">
                <span style="font-size:14px; font-weight:600;">🤖 <?php esc_html_e('AI Deliverability Analysis', 'pointnet-mailguard'); ?></span>
                <button type="button" id="pn-ai-analyze-btn" class="button button-primary">
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
        ?>
        <div style="background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:16px;">
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:12px;">
                <span style="font-size:16px;">💬</span>
                <span style="font-size:14px; font-weight:600;"><?php esc_html_e('Chat with AI', 'pointnet-mailguard'); ?></span>
                <span style="font-size:11px; color:#999;"><?php esc_html_e('Ask anything about email deliverability', 'pointnet-mailguard'); ?></span>
            </div>
            <div class="pn-chat-messages" style="max-height:400px; overflow-y:auto; margin-bottom:12px; padding:8px; background:#f8f8f8; border-radius:6px; min-height:60px; font-size:13px; line-height:1.5;">
                <p style="color:#999; margin:0; text-align:center;"><?php esc_html_e('Ask a question below to get started.', 'pointnet-mailguard'); ?></p>
            </div>
            <div style="display:flex; gap:8px;">
                <textarea class="pn-chat-input" style="flex:1; padding:8px 10px; font-size:13px; border:1px solid #dcdcde; border-radius:4px; resize:vertical; min-height:40px; max-height:120px;" placeholder="<?php esc_attr_e('e.g. Come posso configurare SPF per il mio dominio?', 'pointnet-mailguard'); ?>"></textarea>
                <button type="button" class="button button-primary pn-chat-send-btn" style="align-self:flex-end;">
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

        <!-- PointNet promo -->
        <div style="background:#f8f8f8; border:1px solid #e0e0e0; border-radius:8px; padding:16px 20px; display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap;">
            <div>
                <p style="font-size:14px; font-weight:600; margin:0 0 4px;"><?php esc_html_e('Need professional help with email deliverability?', 'pointnet-mailguard'); ?></p>
                <p style="font-size:13px; color:#666; margin:0;"><?php esc_html_e('PointNet offers SPF/DMARC/DKIM setup, dedicated mail server configuration and deliverability consulting.', 'pointnet-mailguard'); ?></p>
            </div>
            <a href="https://www.pointnet.it/" target="_blank" class="button button-secondary" style="white-space:nowrap;">
                <?php esc_html_e('Contact PointNet →', 'pointnet-mailguard'); ?>
            </a>
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

        // DNS configuration
        $spf_data   = $domain ? PN_Mailguard_SPF::analyze($domain) : null;
        $dmarc_data = $domain ? PN_Mailguard_DMARC::analyze($domain) : null;
        $dkim_data  = ($domain && $dkim_sel) ? PN_Mailguard_DKIM::analyze($domain, $dkim_sel) : null;

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
                'domain' => $domain,
                'spf'    => $spf_data,
                'dmarc'  => $dmarc_data,
                'dkim'   => $dkim_data,
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

        PN_Mailguard_Scanner::run_scheduled();

        wp_send_json_success(['message' => 'Scheduled scan completed.']);
    }

    public static function ajax_start_scan_email(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

        $email = get_option('pn_mailguard_check_email', '');
        if (empty($email)) {
            wp_send_json_error(['message' => 'No email configured.']);
        }

        $data = PN_Mailguard_Scanner::run_email($email);
        PN_Mailguard_Logger::save($data, 'email');
        PN_Mailguard_Mailer::maybe_send($data, 'email');

        wp_send_json_success();
    }

    public static function ajax_start_scan_ip(): void {
        check_ajax_referer('pn_mailguard_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('0', 403);

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
}
