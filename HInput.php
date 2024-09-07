<?php

final class HInput {
    private $input;
    private $password;
    private $time_target;
    private $cost;
    private $plain;
    public $return;

    public function __construct($password = null) {
        $this->input = $password;
        $this->return = $this->input;
        $this->time_target = 0.05;
        $this->plain = $password;
    }

    // Improved hashing method
    public function hash() {
        $this->cost = 8;
        do {
            ++$this->cost;
            $start = microtime(true);
            $this->password = password_hash(stripslashes($this->input), PASSWORD_BCRYPT, ['cost' => $this->cost]);
            $end = microtime(true);
        } while (($end - $start) < $this->time_target);

        if ($this->password === false) {
            return $this->handleError("HASH_ERROR", "Failed to hash the password.");
        }

        return $this->password;
    }

    // Method to check if the password needs rehashing
    public function rehash($password_hash) {
        if (password_needs_rehash($password_hash, PASSWORD_BCRYPT, ['cost' => $this->cost])) {
            return true;
        }
        return false;
    }

    // Method to verify password
    public function match($password_hash) {
        if (password_verify($this->plain, $password_hash)) {
            return true;
        }

        return $this->handleError("MATCH_ERROR", "Password does not match.");
    }

    // Error handling method
    private function handleError($code, $message) {
        return [
            'code' => $code,
            'message' => $message
        ];
    }

    // Method to convert numbers to K, M, G, T
    public static function number_count($n): string {
        $s = array('K', 'M', 'G', 'T');
        $out = '';
        while ($n >= 1000 && count($s) > 0) {
            $n = $n / 1000.0;
            $out = array_shift($s);
        }
        return round($n, max(0, 3 - strlen((int)$n))) . "$out";
    }

    // Method to convert bytes to human-readable sizes
    public static function size(int $bytes, $precision = 2): string {
        $kilobyte = 1024;
        $megabyte = $kilobyte * 1024;
        $gigabyte = $megabyte * 1024;
        $terabyte = $gigabyte * 1024;

        if ($bytes < $kilobyte) {
            return $bytes . 'B';
        } elseif ($bytes < $megabyte) {
            return round($bytes / $kilobyte, $precision) . 'KB';
        } elseif ($bytes < $gigabyte) {
            return round($bytes / $megabyte, $precision) . 'MB';
        } elseif ($bytes < $terabyte) {
            return round($bytes / $gigabyte, $precision) . 'GB';
        } else {
            return round($bytes / $terabyte, $precision) . 'TB';
        }
    }

    // Method to calculate percentage
    public static function percent($number, $of): string {
        return round(($number / $of) * 100, 2) . '%';
    }

    // Method to get client IP address
    public static function get_client_ip_address(): string {
        $ip = " ";
        if (!empty($_SERVER["HTTP_CLIENT_IP"])) {
            $ip = ' ' . $_SERVER["HTTP_CLIENT_IP"];
        }
        if (!empty($_SERVER["HTTP_X_FORWARDED_FOR"])) {
            $ip = ' ' . $_SERVER["HTTP_X_FORWARDED_FOR"];
        }
        if (!empty($_SERVER["REMOTE_ADDR"])) {
            $ip = ' ' . $_SERVER["REMOTE_ADDR"];
        }
        return trim(preg_replace("/[^0-9\.\:]/", "", $ip));
    }

    // Method to encrypt a string
    public static function encrypt_string(string $string, string $encryption_key, $options = 0): string {
        $ciphering = "AES-128-CTR";
        $encryption_iv = '1234567891011121';
        $encryption = openssl_encrypt($string, $ciphering, $encryption_key, $options, $encryption_iv);
        return $encryption;
    }

    // Method to decrypt a string
    public static function decrypt_string(string $string, string $encryption_key, $options = 0): string {
        $ciphering = "AES-128-CTR";
        $encryption_iv = '1234567891011121';
        $decryption = openssl_decrypt($string, $ciphering, $encryption_key, $options, $encryption_iv);
        return $decryption;
    }

    // Method to calculate time difference
    public static function time(string $time, bool $full = false, bool $use_24_hour = true): string {
        $diff = abs(time() - strtotime($time));
        $years = floor($diff / (365 * 60 * 60 * 24));
        $months = floor(($diff - $years * 365 * 60 * 60 * 24) / (30 * 60 * 60 * 24));
        $days = floor(($diff - $years * 365 * 60 * 60 * 24 - $months * 30 * 60 * 60 * 24) / (60 * 60 * 24));
        $hours = round(abs(time() - strtotime($time)) / 60 / 60, 0);
        $minutes = round(abs(time() - strtotime($time)) / 60, 0);

        $time_format = $use_24_hour ? 'H:i' : 'h:i A';

        if ($minutes < 1) {
            return 'Just Now';
        } elseif ($minutes < 60) {
            return $minutes . 'm';
        } elseif ($hours < 24) {
            return $hours . 'h';
        } elseif ($days < 30) {
            return $days . 'd';
        } elseif ($months < 12) {
            return date('l', strtotime($time)) . ' ' . date($time_format, strtotime($time));
        } elseif ($years < 10) {
            return $years . 'y';
        } else {
            return date('M, d Y ' . $time_format, strtotime($time));
        }
    }

    // Method to check if a string starts with a specified substring
    public static function starts_with(string $string, string $startString): bool {
        $len = strlen($startString);
        return (substr($string, 0, $len) === $startString);
    }

    // Method to check if a string ends with a specified substring
    public static function ends_with(string $string, string $endString): bool {
        $len = strlen($endString);
        if ($len == 0) return true;
        return (substr($string, -$len) === $endString);
    }

    // Method to implement rate limiting
    public static function rateLimit($max_requests, $period_in_seconds) {
        $client_ip = $_SERVER['REMOTE_ADDR'];
        $file = sys_get_temp_dir() . "/rate_limit_" . md5($client_ip);

        if (file_exists($file)) {
            $data = json_decode(file_get_contents($file), true);

            if (time() - $data['timestamp'] < $period_in_seconds) {
                if ($data['count'] >= $max_requests) {
                    header('HTTP/1.1 429 Too Many Requests');
                    die('You have exceeded the rate limit.');
                } else {
                    $data['count']++;
                }
            } else {
                $data['timestamp'] = time();
                $data['count'] = 1;
            }
        } else {
            $data = [
                'timestamp' => time(),
                'count' => 1
            ];
        }

        file_put_contents($file, json_encode($data));
    }
}
