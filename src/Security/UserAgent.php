<?php

declare(strict_types=1);

namespace WPRestAuth\AuthToolkit\Security;

/**
 * User Agent Handler
 *
 * Extracts and sanitizes User-Agent strings from HTTP requests.
 * Used for security metadata and session tracking.
 *
 * @package WPRestAuth\AuthToolkit\Security
 */
class UserAgent
{
    private const DEFAULT_USER_AGENT = 'Unknown';
    private const MAX_LENGTH = 500;

    /**
     * Get user agent string from current request
     *
     * @return string Sanitized user agent string
     */
    public static function get(): string
    {
        if (!isset($_SERVER['HTTP_USER_AGENT'])) {
            return self::DEFAULT_USER_AGENT;
        }

        $user_agent = $_SERVER['HTTP_USER_AGENT'];

        // Sanitize for security
        $user_agent = self::sanitize($user_agent);

        // Limit length to prevent abuse
        if (strlen($user_agent) > self::MAX_LENGTH) {
            $user_agent = substr($user_agent, 0, self::MAX_LENGTH);
        }

        return $user_agent ?: self::DEFAULT_USER_AGENT;
    }

    /**
     * Sanitize user agent string
     *
     * @param string $user_agent Raw user agent
     * @return string Sanitized user agent
     */
    private static function sanitize(string $user_agent): string
    {
        // Use WordPress sanitization if available
        if (function_exists('sanitize_text_field')) {
            return sanitize_text_field($user_agent);
        }

        // Basic sanitization
        return filter_var(
            $user_agent,
            FILTER_SANITIZE_STRING,
            FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH
        );
    }

    /**
     * Check if user agent is a bot/crawler
     *
     * @param string|null $user_agent User agent string (null = auto-detect)
     * @return bool True if bot detected
     */
    public static function isBot(?string $user_agent = null): bool
    {
        $user_agent = $user_agent ?? self::get();
        $user_agent = strtolower($user_agent);

        $bot_patterns = [
            'bot', 'crawler', 'spider', 'scraper',
            'googlebot', 'bingbot', 'slurp', 'duckduckbot',
            'baiduspider', 'yandexbot', 'facebookexternalhit'
        ];

        foreach ($bot_patterns as $pattern) {
            if (strpos($user_agent, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract browser name from user agent
     *
     * @param string|null $user_agent User agent string (null = auto-detect)
     * @return string Browser name (Chrome, Firefox, Safari, etc.)
     */
    public static function getBrowser(?string $user_agent = null): string
    {
        $user_agent = $user_agent ?? self::get();
        $user_agent = strtolower($user_agent);

        $browsers = [
            'chrome'  => 'Chrome',
            'firefox' => 'Firefox',
            'safari'  => 'Safari',
            'edge'    => 'Edge',
            'opera'   => 'Opera',
            'msie'    => 'IE',
            'trident' => 'IE',
        ];

        foreach ($browsers as $key => $name) {
            if (strpos($user_agent, $key) !== false) {
                return $name;
            }
        }

        return 'Unknown';
    }

    /**
     * Extract OS from user agent
     *
     * @param string|null $user_agent User agent string (null = auto-detect)
     * @return string Operating system (Windows, Mac, Linux, etc.)
     */
    public static function getOs(?string $user_agent = null): string
    {
        $user_agent = $user_agent ?? self::get();
        $user_agent = strtolower($user_agent);

        $os_list = [
            'windows nt 10'    => 'Windows 10',
            'windows nt 11'    => 'Windows 11',
            'windows nt 6.3'   => 'Windows 8.1',
            'windows nt 6.2'   => 'Windows 8',
            'windows nt 6.1'   => 'Windows 7',
            'windows'          => 'Windows',
            'mac os x'         => 'macOS',
            'macintosh'        => 'macOS',
            'linux'            => 'Linux',
            'ubuntu'           => 'Ubuntu',
            'android'          => 'Android',
            'iphone'           => 'iOS',
            'ipad'             => 'iOS',
        ];

        foreach ($os_list as $key => $name) {
            if (strpos($user_agent, $key) !== false) {
                return $name;
            }
        }

        return 'Unknown';
    }

    /**
     * Check if user agent is mobile device
     *
     * @param string|null $user_agent User agent string (null = auto-detect)
     * @return bool True if mobile
     */
    public static function isMobile(?string $user_agent = null): bool
    {
        $user_agent = $user_agent ?? self::get();
        $user_agent = strtolower($user_agent);

        $mobile_keywords = [
            'mobile', 'android', 'iphone', 'ipad', 'ipod',
            'blackberry', 'windows phone', 'webos'
        ];

        foreach ($mobile_keywords as $keyword) {
            if (strpos($user_agent, $keyword) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse user agent into structured data
     *
     * @param string|null $user_agent User agent string (null = auto-detect)
     * @return array{raw: string, browser: string, os: string, is_mobile: bool, is_bot: bool}
     */
    public static function parse(?string $user_agent = null): array
    {
        $user_agent = $user_agent ?? self::get();

        return [
            'raw'       => $user_agent,
            'browser'   => self::getBrowser($user_agent),
            'os'        => self::getOs($user_agent),
            'is_mobile' => self::isMobile($user_agent),
            'is_bot'    => self::isBot($user_agent),
        ];
    }
}
