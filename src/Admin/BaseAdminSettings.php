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
        register_setting(
            $this->getOptionGroup(),
            $this->getCookieSettingsOption(),
            [
                'type' => 'array',
                'sanitize_callback' => [$this, 'sanitizeCookieSettings'],
                'default' => [
                    'samesite' => 'auto',
                    'secure' => 'auto',
                    'path' => 'auto',
                    'domain' => 'auto',
                ],
            ]
        );

        add_settings_section(
            'cookie_config_section',
            'Cookie Configuration',
            [$this, 'cookieConfigSection'],
            $page_id
        );

        add_settings_field(
            'cookie_samesite',
            'SameSite Attribute',
            [$this, 'cookieSamesiteField'],
            $page_id,
            'cookie_config_section'
        );

        add_settings_field(
            'cookie_secure',
            'Secure Attribute',
            [$this, 'cookieSecureField'],
            $page_id,
            'cookie_config_section'
        );

        add_settings_field(
            'cookie_path',
            'Cookie Path',
            [$this, 'cookiePathField'],
            $page_id,
            'cookie_config_section'
        );

        add_settings_field(
            'cookie_domain',
            'Cookie Domain',
            [$this, 'cookieDomainField'],
            $page_id,
            'cookie_config_section'
        );
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
        $value = $settings['cors_allowed_origins'] ?? "http://localhost:3000\nhttp://localhost:5173\nhttp://localhost:5174\nhttp://localhost:5175";
        ?>
        <textarea name="<?php echo esc_attr($this->getGeneralSettingsOption()); ?>[cors_allowed_origins]" class="large-text" rows="5"><?php echo esc_textarea($value); ?></textarea>
        <p class="description">One origin per line. Use * to allow all origins (not recommended for production).</p>
        <?php
    }

    /**
     * Render cookie configuration section
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
        ?>
        <p><?php esc_html_e('Configure cookie security settings for refresh tokens. Settings are automatically configured based on your environment. Use "Auto" to let the plugin detect appropriate settings.', 'wp-rest-auth-toolkit'); ?></p>

        <div class="notice notice-info inline">
            <p>
                <strong><?php esc_html_e('Current Environment:', 'wp-rest-auth-toolkit'); ?></strong>
                <code><?php echo esc_html($environment); ?></code>
            </p>
        </div>

        <div class="notice notice-warning inline">
            <h4><?php esc_html_e('Active Cookie Configuration', 'wp-rest-auth-toolkit'); ?></h4>
            <table class="widefat" style="max-width: 600px;">
                <tbody>
                    <tr>
                        <td><strong><?php esc_html_e('SameSite:', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['samesite']); ?></code></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('Secure:', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['secure'] ? 'true' : 'false'); ?></code></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('Path:', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['path']); ?></code></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('Domain:', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['domain'] ?: '(current domain)'); ?></code></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('HttpOnly:', 'wp-rest-auth-toolkit'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['httponly'] ? 'true' : 'false'); ?></code></td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="notice notice-info inline">
            <h4><?php esc_html_e('Environment Detection Logic', 'wp-rest-auth-toolkit'); ?></h4>
            <ul>
                <li><strong><?php esc_html_e('Development:', 'wp-rest-auth-toolkit'); ?></strong>
                    <?php esc_html_e('localhost, *.local, *.test domains OR WP_DEBUG enabled', 'wp-rest-auth-toolkit'); ?>
                </li>
                <li><strong><?php esc_html_e('Staging:', 'wp-rest-auth-toolkit'); ?></strong>
                    <?php esc_html_e('Domains containing "staging", "dev", or "test"', 'wp-rest-auth-toolkit'); ?>
                </li>
                <li><strong><?php esc_html_e('Production:', 'wp-rest-auth-toolkit'); ?></strong>
                    <?php esc_html_e('All other domains', 'wp-rest-auth-toolkit'); ?>
                </li>
            </ul>
        </div>
        <?php
    }

    /**
     * Render SameSite field
     */
    public function cookieSamesiteField(): void
    {
        $cookie_class = $this->getCookieConfigClass();
        $defaults = class_exists($cookie_class) ? $cookie_class::get_defaults() : ['samesite' => 'auto'];
        $config = get_option($this->getCookieSettingsOption(), $defaults);
        $value = $config['samesite'] ?? 'auto';
        ?>
        <select name="<?php echo esc_attr($this->getCookieSettingsOption()); ?>[samesite]">
            <option value="auto" <?php selected($value, 'auto'); ?>>
                <?php esc_html_e('Auto (Recommended)', 'wp-rest-auth-toolkit'); ?>
            </option>
            <option value="None" <?php selected($value, 'None'); ?>>
                <?php esc_html_e('None (Cross-site allowed)', 'wp-rest-auth-toolkit'); ?>
            </option>
            <option value="Lax" <?php selected($value, 'Lax'); ?>>
                <?php esc_html_e('Lax (Relaxed)', 'wp-rest-auth-toolkit'); ?>
            </option>
            <option value="Strict" <?php selected($value, 'Strict'); ?>>
                <?php esc_html_e('Strict (Maximum security)', 'wp-rest-auth-toolkit'); ?>
            </option>
        </select>
        <p class="description">
            <?php esc_html_e('Auto: None (development), Lax (staging), Strict (production)', 'wp-rest-auth-toolkit'); ?>
        </p>
        <?php
    }

    /**
     * Render Secure field
     */
    public function cookieSecureField(): void
    {
        $cookie_class = $this->getCookieConfigClass();
        $defaults = class_exists($cookie_class) ? $cookie_class::get_defaults() : ['secure' => 'auto'];
        $config = get_option($this->getCookieSettingsOption(), $defaults);
        $value = $config['secure'] ?? 'auto';
        ?>
        <select name="<?php echo esc_attr($this->getCookieSettingsOption()); ?>[secure]">
            <option value="auto" <?php selected($value, 'auto'); ?>>
                <?php esc_html_e('Auto (Recommended)', 'wp-rest-auth-toolkit'); ?>
            </option>
            <option value="1" <?php selected($value, '1'); ?>>
                <?php esc_html_e('Enabled (HTTPS required)', 'wp-rest-auth-toolkit'); ?>
            </option>
            <option value="0" <?php selected($value, '0'); ?>>
                <?php esc_html_e('Disabled (HTTP allowed)', 'wp-rest-auth-toolkit'); ?>
            </option>
        </select>
        <p class="description">
            <?php esc_html_e('Auto: Enabled for staging/production, disabled for development without HTTPS', 'wp-rest-auth-toolkit'); ?>
        </p>
        <?php
    }

    /**
     * Render Path field
     */
    public function cookiePathField(): void
    {
        $cookie_class = $this->getCookieConfigClass();
        $defaults = class_exists($cookie_class) ? $cookie_class::get_defaults() : ['path' => 'auto'];
        $config = get_option($this->getCookieSettingsOption(), $defaults);
        $value = $config['path'] ?? 'auto';
        ?>
        <input type="text"
            name="<?php echo esc_attr($this->getCookieSettingsOption()); ?>[path]"
            value="<?php echo esc_attr($value); ?>"
            class="regular-text"
            placeholder="auto"
        />
        <p class="description">
            <?php esc_html_e('Auto: "/" (development), specific API path (staging/production)', 'wp-rest-auth-toolkit'); ?>
        </p>
        <?php
    }

    /**
     * Render Domain field
     */
    public function cookieDomainField(): void
    {
        $cookie_class = $this->getCookieConfigClass();
        $defaults = class_exists($cookie_class) ? $cookie_class::get_defaults() : ['domain' => 'auto'];
        $config = get_option($this->getCookieSettingsOption(), $defaults);
        $value = $config['domain'] ?? 'auto';
        ?>
        <input type="text"
            name="<?php echo esc_attr($this->getCookieSettingsOption()); ?>[domain]"
            value="<?php echo esc_attr($value); ?>"
            class="regular-text"
            placeholder="auto"
        />
        <p class="description">
            <?php esc_html_e('Auto: Empty (current domain only). Use for subdomain sharing (e.g., ".example.com")', 'wp-rest-auth-toolkit'); ?>
        </p>
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
     * Sanitize cookie settings
     *
     * @param array|null $input Input settings
     * @return array Sanitized settings
     */
    public function sanitizeCookieSettings($input): array
    {
        $cookie_class = $this->getCookieConfigClass();
        $defaults = [
            'samesite' => 'auto',
            'secure' => 'auto',
            'path' => 'auto',
            'domain' => 'auto',
        ];
        $existing = get_option($this->getCookieSettingsOption(), $defaults);

        if (!is_array($input)) {
            return $existing;
        }

        $sanitized = $existing;

        // Sanitize SameSite
        if (isset($input['samesite'])) {
            $valid_samesite = ['auto', 'None', 'Lax', 'Strict'];
            $sanitized['samesite'] = in_array($input['samesite'], $valid_samesite, true) ? $input['samesite'] : 'auto';
        }

        // Sanitize Secure
        if (isset($input['secure'])) {
            if ('auto' === $input['secure']) {
                $sanitized['secure'] = 'auto';
            } else {
                $sanitized['secure'] = in_array($input['secure'], ['1', 1, true], true) ? '1' : '0';
            }
        }

        // Sanitize Path
        if (isset($input['path'])) {
            $sanitized['path'] = 'auto' === $input['path'] ? 'auto' : sanitize_text_field($input['path']);
        }

        // Sanitize Domain
        if (isset($input['domain'])) {
            $sanitized['domain'] = 'auto' === $input['domain'] ? 'auto' : sanitize_text_field($input['domain']);
        }

        // Clear cache after saving (if class exists)
        if (class_exists($cookie_class) && method_exists($cookie_class, 'clear_cache')) {
            $cookie_class::clear_cache();
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
                'cors_allowed_origins' => "http://localhost:3000\nhttp://localhost:5173\nhttp://localhost:5174\nhttp://localhost:5175",
            ]
        );
    }
}
