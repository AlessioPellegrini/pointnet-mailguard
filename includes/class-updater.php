<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Updater
 *
 * Lightweight native GitHub Release updater for PointNet Mail Guard.
 * Checks GitHub repository releases and git tags, informs WordPress of available updates,
 * and ensures safe installation with correct folder naming.
 */
class PN_Mailguard_Updater {

    private const GITHUB_REPO   = 'AlessioPellegrini/pointnet-mailguard';
    private const TRANSIENT_KEY = 'pn_mailguard_github_release';
    private const CACHE_TTL     = 43200; // 12 hours

    /**
     * Hook updater into WordPress.
     */
    public static function init(): void {
        add_filter('pre_set_site_transient_update_plugins', [__CLASS__, 'check_update']);
        add_filter('plugins_api',                            [__CLASS__, 'plugin_info'], 20, 3);
        add_filter('upgrader_source_selection',             [__CLASS__, 'fix_folder_name'], 10, 4);
        add_action('upgrader_process_complete',             [__CLASS__, 'clear_cache'], 10, 2);
    }

    /**
     * Retrieve the latest release or git tag from GitHub API with transient caching.
     */
    public static function get_latest_release(bool $force_refresh = false): ?array {
        if (!$force_refresh && !empty($_GET['force-check'])) {
            $force_refresh = true;
        }

        if (!$force_refresh) {
            $cached = get_site_transient(self::TRANSIENT_KEY);
            if ($cached !== false && is_array($cached)) {
                return $cached;
            }
        }

        $user_agent = 'WordPress/' . get_bloginfo('version') . '; PointNetMailGuard/' . PN_MAILGUARD_VERSION . '; ' . home_url();

        // 1. Check formal GitHub Releases
        $rel_url = 'https://api.github.com/repos/' . self::GITHUB_REPO . '/releases';
        $rel_res = wp_remote_get($rel_url, [
            'timeout'    => 10,
            'user-agent' => $user_agent,
            'headers'    => ['Accept' => 'application/vnd.github.v3+json'],
        ]);

        $best_release = null;
        if (!is_wp_error($rel_res) && wp_remote_retrieve_response_code($rel_res) === 200) {
            $releases = json_decode(wp_remote_retrieve_body($rel_res), true);
            if (is_array($releases) && !empty($releases)) {
                foreach ($releases as $rel) {
                    if (!empty($rel['draft'])) continue;
                    $v = ltrim($rel['tag_name'] ?? '', 'vV ');
                    if (!$best_release || version_compare($v, ltrim($best_release['tag_name'], 'vV '), '>')) {
                        $best_release = $rel;
                    }
                }
            }
        }

        // 2. Also check Git Tags in case tags were pushed without creating a formal GitHub release
        $tags_url = 'https://api.github.com/repos/' . self::GITHUB_REPO . '/tags';
        $tags_res = wp_remote_get($tags_url, [
            'timeout'    => 10,
            'user-agent' => $user_agent,
            'headers'    => ['Accept' => 'application/vnd.github.v3+json'],
        ]);

        if (!is_wp_error($tags_res) && wp_remote_retrieve_response_code($tags_res) === 200) {
            $tags = json_decode(wp_remote_retrieve_body($tags_res), true);
            if (is_array($tags) && !empty($tags)) {
                foreach ($tags as $tag_item) {
                    $tv = ltrim($tag_item['name'] ?? '', 'vV ');
                    $current_best_v = $best_release ? ltrim($best_release['tag_name'], 'vV ') : '0.0.0';
                    if (version_compare($tv, $current_best_v, '>')) {
                        $best_release = [
                            'tag_name'    => $tag_item['name'],
                            'zipball_url' => $tag_item['zipball_url'] ?? ('https://api.github.com/repos/' . self::GITHUB_REPO . '/zipball/refs/tags/' . $tag_item['name']),
                            'html_url'    => 'https://github.com/' . self::GITHUB_REPO . '/releases/tag/' . $tag_item['name'],
                            'body'        => '',
                            'assets'      => [],
                        ];
                    }
                }
            }
        }

        if (!$best_release || empty($best_release['tag_name'])) {
            return null;
        }

        set_site_transient(self::TRANSIENT_KEY, $best_release, self::CACHE_TTL);
        return $best_release;
    }

    /**
     * Check if a newer release is available and inject it into WordPress update transient.
     */
    public static function check_update($transient) {
        if (!is_object($transient)) {
            return $transient;
        }

        $release = self::get_latest_release();
        if (!$release) {
            return $transient;
        }

        $plugin_file = plugin_basename(PN_MAILGUARD_PLUGIN_FILE);
        $latest_ver  = ltrim($release['tag_name'], 'vV ');

        // Prefer attached zip asset if published, fallback to GitHub zipball
        $package = $release['zipball_url'] ?? '';
        if (!empty($release['assets']) && is_array($release['assets'])) {
            foreach ($release['assets'] as $asset) {
                if (isset($asset['name']) && $asset['name'] === 'pointnet-mailguard.zip' && !empty($asset['browser_download_url'])) {
                    $package = $asset['browser_download_url'];
                    break;
                }
            }
        }

        $item = (object) [
            'slug'         => 'pointnet-mailguard',
            'plugin'       => $plugin_file,
            'new_version'  => $latest_ver,
            'url'          => $release['html_url'] ?? 'https://github.com/' . self::GITHUB_REPO,
            'package'      => $package,
            'tested'       => '7.1',
            'requires_php' => '8.3',
            'icons'        => [],
            'banners'      => [],
        ];

        if (version_compare($latest_ver, PN_MAILGUARD_VERSION, '>')) {
            $transient->response[$plugin_file] = $item;
        } else {
            $transient->no_update[$plugin_file] = $item;
        }

        return $transient;
    }

    /**
     * Provide plugin information for the WordPress "View version details" modal.
     */
    public static function plugin_info($res, string $action, $args) {
        if ($action !== 'plugin_information') {
            return $res;
        }

        if (empty($args->slug) || $args->slug !== 'pointnet-mailguard') {
            return $res;
        }

        $release = self::get_latest_release();
        if (!$release) {
            return $res;
        }

        $latest_ver = ltrim($release['tag_name'], 'vV ');
        $changelog  = !empty($release['body'])
            ? nl2br(esc_html($release['body']))
            : __('Consult GitHub releases for full changelog.', 'pointnet-mailguard');

        return (object) [
            'name'          => 'PointNet Mail Guard',
            'slug'          => 'pointnet-mailguard',
            'version'       => $latest_ver,
            'author'        => '<a href="https://www.pointnet.it/">PointNet</a>',
            'homepage'      => 'https://www.pointnet.it/',
            'requires'      => '7.0',
            'tested'        => '7.1',
            'requires_php'  => '8.3',
            'download_link' => $release['zipball_url'] ?? '',
            'sections'      => [
                'description' => __('Complete email deliverability monitoring. Checks DNSBL blacklists, PTR record and SMTP configuration natively in PHP — no external dependencies required.', 'pointnet-mailguard'),
                'changelog'   => $changelog,
            ],
        ];
    }

    /**
     * Ensure the extracted directory is named 'pointnet-mailguard' so WordPress updates it in place.
     */
    public static function fix_folder_name($source, string $remote_source, $upgrader, array $hook_extra = []) {
        global $wp_filesystem;

        $plugin_file = plugin_basename(PN_MAILGUARD_PLUGIN_FILE);
        if (empty($hook_extra['plugin']) || $hook_extra['plugin'] !== $plugin_file) {
            return $source;
        }

        $correct_dir_name = dirname($plugin_file);
        $target = trailingslashit($remote_source) . $correct_dir_name;

        if (untrailingslashit($source) === untrailingslashit($target)) {
            return $source;
        }

        if (!$wp_filesystem) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }

        if ($wp_filesystem && $wp_filesystem->move($source, $target)) {
            return trailingslashit($target);
        }

        return new WP_Error(
            'pn_mailguard_rename_failed',
            __('Failed to rename plugin update folder to pointnet-mailguard.', 'pointnet-mailguard')
        );
    }

    /**
     * Clear release transient cache when upgrade process finishes.
     */
    public static function clear_cache($upgrader, array $hook_extra = []): void {
        delete_site_transient(self::TRANSIENT_KEY);
    }
}
