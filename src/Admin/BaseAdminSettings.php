<?php

/**
 * Base Admin Settings class
 * Provides shared functionality for admin settings pages
 *
 * @package WPRestAuth\AuthToolkit
 */

namespace WPRestAuth\AuthToolkit\Admin;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Base class for admin settings pages
 */
abstract class BaseAdminSettings
{
    /**
     * Get the option group name
     *
     * @return string
     */
    abstract protected function getOptionGroup(): string;

    /**
     * Get the general settings option name
     *
     * @return string
     */
    abstract protected function getGeneralSettingsOption(): string;

    /**
     * Get the cookie settings option name
     *
     * @return string
     */
    abstract protected function getCookieSettingsOption(): string;

    /**
     * Get the settings page slug
     *
     * @return string
     */
    abstract protected function getPageSlug(): string;

    /**
     * Get the cookie config class name
     *
     * @return string
     */
    abstract protected function getCookieConfigClass(): string;

    /**
     * Get the cookie name (optional - override in child class if needed)
     *
     * @return string|null
     */
    protected function getCookieName(): ?string
    {
        return null;
    }

    /**
     * Get the cookie constant prefix for documentation
     *
     * @return string
     */
    protected function getCookieConstantPrefix(): string
    {
        return 'COOKIE_CONFIG';
    }

    /**
     * Get the cookie filter prefix for documentation
     *
     * @return string
     */
    protected function getCookieFilterPrefix(): string
    {
        return 'cookie_config';
    }

    /**
     * Register General Settings section and fields
     *
     * @param string $page_id The page ID to register settings on
     */
    public function registerGeneralSettings(string $page_id): void
    {
        register_setting(
            $this->getOptionGroup(),
            $this->getGeneralSettingsOption(),
            [
                'sanitize_callback' => [$this, 'sanitizeGeneralSettings']
            ]
        );

        add_settings_section(
            'general_settings',
            'General Settings',
            [$this, 'generalSettingsSection'],
            $page_id
        );

        add_settings_field(
            'enable_debug_logging',
            'Enable Debug Logging',
            [$this, 'enableDebugLoggingField'],
            $page_id,
            'general_settings'
        );

        add_settings_field(
            'cors_allowed_origins',
            'CORS Allowed Origins',
            [$this, 'corsAllowedOriginsField'],
            $page_id,
            'general_settings'
        );
    }

    /**
     * Register Cookie Settings section and fields
     *
     * @param string $page_id The page ID to register settings on
     */
    public function registerCookieSettings(string $page_id): void
    {
        // Cookie settings are read-only, no need to register for saving
        // Configuration is done via constants or filters

        add_settings_section(
            'cookie_config_section',
            'Cookie Configuration',
            [$this, 'cookieConfigSection'],
            $page_id
        );

        // No individual fields - everything is displayed in the section callback
    }

    /**
     * Render general settings section description
     */
    public function generalSettingsSection(): void
    {
        echo '<p>General plugin settings and security options.</p>';
    }

    /**
     * Render debug logging field
     */
    public function enableDebugLoggingField(): void
    {
        $settings = get_option($this->getGeneralSettingsOption(), []);
        $checked = isset($settings['enable_debug_logging']) && $settings['enable_debug_logging'];
        ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->getGeneralSettingsOption()); ?>[enable_debug_logging]" value="1" <?php checked($checked); ?> />
            Enable detailed logging for authentication events
        </label>
        <p class="description">Logs will be written to your WordPress debug log. Ensure WP_DEBUG_LOG is enabled.</p>
        <?php
    }

    /**
     * Render CORS allowed origins field
     */
    public function corsAllowedOriginsField(): void
    {
        $settings = get_option($this->getGeneralSettingsOption(), []);
        $value = $settings['cors_allowed_origins'] ?? '';
        ?>
        <textarea name="<?php echo esc_attr($this->getGeneralSettingsOption()); ?>[cors_allowed_origins]" class="large-text" rows="5"><?php echo esc_textarea($value); ?></textarea>
        <p class="description">One origin per line. Use * to allow all origins (not recommended for production).</p>
        <?php
    }

    /**
     * Render cookie configuration section (read-only display)
     */
    public function cookieConfigSection(): void
    {
        $cookie_class = $this->getCookieConfigClass();

        if (!class_exists($cookie_class)) {
            ?>
            <div class="notice notice-error inline">
                <p><?php esc_html_e('Cookie configuration class not loaded. Please check plugin installation.', 'wp-rest-auth-toolkit'); ?></p>
            </div>
            <?php
            return;
        }

        $environment = $cookie_class::get_environment();
        $current_config = $cookie_class::get_config();

        // Get cookie name if available from child class
        $cookie_name = $this->getCookieName();
        if ($cookie_name) {
            $current_config['name'] = $cookie_name;
        }

        // In development, show the actual secure flag based on current request
        if ('development' === $environment) {
            $current_config['secure'] = is_ssl();
        }
        ?>
        <p style="font-size: 14px; line-height: 1.6;">
            <?php esc_html_e('Cookie security settings are automatically configured based on your environment. Configuration can be customized using constants or filters.', 'wp-rest-auth-toolkit'); ?>
            <a href="https://github.com/wp-rest-auth/wp-rest-auth-toolkit/blob/main/docs/cookie-configuration.md" target="_blank" style="text-decoration: none;">
                <?php esc_html_e('View Documentation', 'wp-rest-auth-toolkit'); ?> &rarr;
            </a>
        </p>

        <!-- Detected Environment -->
        <div class="notice notice-info inline" style="margin: 20px 0 15px 0;">
            <h3 style="margin: 0 0 10px 0;">🌍 <?php esc_html_e('Detected Environment', 'wp-rest-auth-toolkit'); ?></h3>
            <p style="font-size: 16px; margin: 5px 0;">
                <code style="font-size: 15px; padding: 5px 10px; background: #fff; border-radius: 3px; font-weight: bold;">
                    <?php echo esc_html(ucfirst($environment)); ?>
                </code>
            </p>
            <p class="description" style="margin-top: 8px;">
                <?php
                switch ($environment) {
                    case 'development':
                        esc_html_e('Detected via: localhost, *.local, *.test domains, or WP_DEBUG=true', 'wp-rest-auth-toolkit');
                        break;
                    case 'staging':
                        esc_html_e('Detected via: domain contains "staging", "dev", or "test"', 'wp-rest-auth-toolkit');
                        break;
                    case 'production':
                        esc_html_e('Detected via: standard production domain', 'wp-rest-auth-toolkit');
                        break;
                }
                ?>
            </p>
        </div>

        <!-- Active Cookie Configuration -->
        <div class="notice notice-success inline" style="margin: 15px 0;">
            <h3 style="margin: 0 0 10px 0;">🍪 <?php esc_html_e('Active Cookie Configuration', 'wp-rest-auth-toolkit'); ?></h3>
            <table class="widefat striped" style="max-width: 100%; margin-top: 10px;">
                <thead>
                    <tr>
                        <th style="width: 25%;"><?php esc_html_e('Setting', 'wp-rest-auth-toolkit'); ?></th>
                        <th style="width: 20%;"><?php esc_html_e('Value', 'wp-rest-auth-toolkit'); ?></th>
                        <th><?php esc_html_e('Description', 'wp-rest-auth-toolkit'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (isset($current_config['name'])): ?>
                    <tr>
                        <td><strong><?php esc_html_e('Cookie Name', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['name']); ?></code></td>
                        <td><?php esc_html_e('Name of the HTTP-only cookie storing the refresh token', 'wp-rest-auth-toolkit'); ?></td>
                    </tr>
                    <?php endif; ?>
                    <tr>
                        <td><strong><?php esc_html_e('SameSite', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['samesite']); ?></code></td>
                        <td>
                            <?php
                            if ('None' === $current_config['samesite']) {
                                esc_html_e('Cross-origin allowed (for SPAs on different domains)', 'wp-rest-auth-toolkit');
                            } elseif ('Lax' === $current_config['samesite']) {
                                esc_html_e('Relaxed protection, top-level navigation allowed', 'wp-rest-auth-toolkit');
                            } else {
                                esc_html_e('Strict protection, same-origin requests only', 'wp-rest-auth-toolkit');
                            }
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('Secure', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['secure'] ? 'true' : 'false'); ?></code></td>
                        <td><?php echo esc_html($current_config['secure'] ? __('Cookie only sent over HTTPS', 'wp-rest-auth-toolkit') : __('Cookie sent over HTTP (⚠️ not recommended for production)', 'wp-rest-auth-toolkit')); ?></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('HttpOnly', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['httponly'] ? 'true' : 'false'); ?></code></td>
                        <td><?php esc_html_e('Cookie not accessible via JavaScript (XSS protection)', 'wp-rest-auth-toolkit'); ?></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('Path', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['path']); ?></code></td>
                        <td><?php esc_html_e('URL path scope where cookie is valid', 'wp-rest-auth-toolkit'); ?></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('Domain', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['domain'] ? $current_config['domain'] : '(current domain)'); ?></code></td>
                        <td><?php esc_html_e('Domain scope where cookie is valid', 'wp-rest-auth-toolkit'); ?></td>
                    </tr>
                    <?php if (isset($current_config['lifetime'])): ?>
                    <tr>
                        <td><strong><?php esc_html_e('Lifetime', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html(human_time_diff(0, $current_config['lifetime'])); ?></code></td>
                        <td><?php esc_html_e('Duration the refresh token remains valid', 'wp-rest-auth-toolkit'); ?></td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <!-- Configuration Priority -->
        <div class="notice notice-info inline" style="margin: 15px 0;">
            <h3 style="margin: 0 0 10px 0;">⚙️ <?php esc_html_e('Configuration Priority', 'wp-rest-auth-toolkit'); ?></h3>
            <p><?php esc_html_e('Settings are applied in the following order (highest to lowest priority):', 'wp-rest-auth-toolkit'); ?></p>
            <ol style="line-height: 2.2; margin: 10px 0 10px 20px;">
                <li>
                    <strong><?php esc_html_e('Constants', 'wp-rest-auth-toolkit'); ?></strong>
                    <code style="font-size: 12px; background: #f0f0f0; padding: 2px 6px; border-radius: 3px;"><?php echo esc_html($this->getCookieConstantPrefix()); ?>_*</code>
                    <em class="description"> — <?php esc_html_e('in wp-config.php', 'wp-rest-auth-toolkit'); ?></em>
                </li>
                <li>
                    <strong><?php esc_html_e('Filters', 'wp-rest-auth-toolkit'); ?></strong>
                    <code style="font-size: 12px; background: #f0f0f0; padding: 2px 6px; border-radius: 3px;"><?php echo esc_html($this->getCookieFilterPrefix()); ?>_*</code>
                    <em class="description"> — <?php esc_html_e('in theme/plugin code', 'wp-rest-auth-toolkit'); ?></em>
                </li>
                <li>
                    <strong><?php esc_html_e('Environment Defaults', 'wp-rest-auth-toolkit'); ?></strong>
                    <em class="description"> — <?php esc_html_e('auto-detected based on environment', 'wp-rest-auth-toolkit'); ?></em>
                </li>
                <li>
                    <strong><?php esc_html_e('Hard-coded Defaults', 'wp-rest-auth-toolkit'); ?></strong>
                    <em class="description"> — <?php esc_html_e('fallback values', 'wp-rest-auth-toolkit'); ?></em>
                </li>
            </ol>
        </div>
        <?php
    }


    /**
     * Sanitize general settings
     *
     * @param array|null $input Raw input values
     * @return array Sanitized values
     */
    public function sanitizeGeneralSettings($input): array
    {
        $existing = get_option($this->getGeneralSettingsOption(), []);

        if (!is_array($input) || empty($input)) {
            return $existing;
        }

        $sanitized = [];

        $sanitized['enable_debug_logging'] = isset($input['enable_debug_logging']) && $input['enable_debug_logging'];

        if (isset($input['cors_allowed_origins'])) {
            $origins = sanitize_textarea_field($input['cors_allowed_origins']);
            $sanitized['cors_allowed_origins'] = $origins;
        }

        return $sanitized;
    }


    /**
     * Get general settings with defaults
     *
     * @return array
     */
    public function getGeneralSettings(): array
    {
        return get_option(
            $this->getGeneralSettingsOption(),
            [
                'enable_debug_logging' => false,
                'cors_allowed_origins' => '',
            ]
        );
    }
}
