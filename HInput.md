# HInput Class

The `HInput` class provides a collection of methods for handling various input and utility functions, including password hashing, encryption, size formatting, rate limiting, and more.

## Installation

To use the `HInput` class, include or autoload the class file in your project:

```php
require 'path/to/HInput.php';
```

## Usage

### Password Handling

#### Constructor

```php
$passwordInput = new HInput("MySecurePassword123");
```

Creates an instance of the `HInput` class with an optional password parameter.

#### hash()

```php
$hashedPassword = $passwordInput->hash();
echo "Hashed Password: " . $hashedPassword . "\n";
```

Hashes the provided password and returns the hashed password.

#### rehash($password_hash)

```php
$needsRehash = $passwordInput->rehash($hashedPassword);
echo "Needs Rehash: " . ($needsRehash ? "Yes" : "No") . "\n";
```

Checks if the provided password hash needs rehashing. Returns `true` if it does, otherwise `false`.

#### match($password_hash)

```php
$passwordMatch = $passwordInput->match($hashedPassword);
echo "Password Match: " . ($passwordMatch ? "Yes" : "No") . "\n";
```

Verifies if the provided password matches the hash. Returns `true` if it matches, otherwise `false`.

### Static Methods

#### number_count($n)

```php
$largeNumber = 1500000;
$numberCount = HInput::number_count($largeNumber);
echo "Number Count: " . $numberCount . "\n";
```

Converts a large number to a human-readable format with suffixes (K, M, G, T).

#### size(int $bytes, $precision = 2)

```php
$fileSize = 15728640; // 15MB
$fileSizeReadable = HInput::size($fileSize);
echo "File Size: " . $fileSizeReadable . "\n";
```

Converts bytes to a human-readable format (B, KB, MB, GB, TB) with a specified precision.

#### percent($number, $of)

```php
$percentValue = HInput::percent(50, 200);
echo "Percent: " . $percentValue . "\n";
```

Calculates the percentage of a number out of another and returns it as a string with a percentage sign.

#### get_client_ip_address()

```php
$clientIP = HInput::get_client_ip_address();
echo "Client IP Address: " . $clientIP . "\n";
```

Retrieves the client's IP address.

#### encrypt_string(string $string, string $encryption_key, $options = 0)

```php
$encryptionKey = "myEncryptionKey123";
$originalString = "Sensitive Data";
$encryptedString = HInput::encrypt_string($originalString, $encryptionKey);
echo "Encrypted String: " . $encryptedString . "\n";
```

Encrypts a string using the specified encryption key and options.

#### decrypt_string(string $string, string $encryption_key, $options = 0)

```php
$decryptedString = HInput::decrypt_string($encryptedString, $encryptionKey);
echo "Decrypted String: " . $decryptedString . "\n";
```

Decrypts an encrypted string using the specified encryption key and options.

#### time(string $time, bool $full = false, bool $use_24_hour = true)

```php
$pastTime = "2023-08-01 14:35:00";
$timeDifference = HInput::time($pastTime, false, false); // Using 12-hour format
echo "Time Difference: " . $timeDifference . "\n";
```

Calculates the time difference and formats it in a readable way, supporting 12-hour or 24-hour format.

#### starts_with(string $string, string $startString)

```php
$string = "Hello, World!";
$startString = "Hello";
$startsWith = HInput::starts_with($string, $startString);
echo "Starts With: " . ($startsWith ? "Yes" : "No") . "\n";
```

Checks if a string starts with a specified substring. Returns `true` if it does, otherwise `false`.

#### ends_with(string $string, string $endString)

```php
$endString = "World!";
$endsWith = HInput::ends_with($string, $endString);
echo "Ends With: " . ($endsWith ? "Yes" : "No") . "\n";
```

Checks if a string ends with a specified substring. Returns `true` if it does, otherwise `false`.

#### rateLimit($max_requests, $period_in_seconds)

```php
HInput::rateLimit(10, 60); // Max 10 requests per 60 seconds
```

Implements rate limiting based on the client's IP address. If the rate limit is exceeded, it sends a 429 Too Many Requests response.

---

### Notes

1. **Error Handling:** The password handling methods (`hash`, `match`) include error handling that returns an array with an error code and a clear message.
2. **Rate Limiting:** The `rateLimit` method is designed for use in a web server environment and might not demonstrate rate limiting behavior in a CLI or local development setup.

Ensure you replace the `require 'path/to/HInput.php';` line with the actual path to your `HInput` class file in your project.
