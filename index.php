<?php

/**
 * Developer: Andy Goldau
 * © 2026 DA-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.
 * 
 * DISCLAIMER: This software is provided "as is" without any warranty of any kind.
 * DA-Register is an independent software solution and is not affiliated with, 
 * endorsed by, or sponsored by JBMC Software (DirectAdmin) or its affiliates.
 */

// Suppress PHP error output to prevent information disclosure
error_reporting(0);
ini_set('display_errors', '0');

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
  || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
  || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

session_start([
  'cookie_httponly' => true,
  'cookie_samesite' => 'Strict',
  'cookie_secure'   => $isHttps,
]);
require_once __DIR__ . '/config.php';

// ── Security Headers ───────────────────────────────────────────────────────
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header(
  "Content-Security-Policy: default-src 'self'; "
  . "script-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://www.google.com https://www.gstatic.com https://cdn.jsdelivr.net "
  . "https://challenges.cloudflare.com https://service.mtcaptcha.com https://service2.mtcaptcha.com; "
  . "frame-src 'self' https://hcaptcha.com https://*.hcaptcha.com https://www.google.com https://challenges.cloudflare.com https://service.mtcaptcha.com https://service2.mtcaptcha.com; "
  . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
  . "font-src 'self' https://fonts.gstatic.com; "
  . "connect-src 'self' https://api.hcaptcha.com https://*.hcaptcha.com https://challenges.cloudflare.com https://www.google.com https://service.mtcaptcha.com https://service2.mtcaptcha.com https://api.pwnedpasswords.com; "
  . "img-src 'self' data: https://*.hcaptcha.com https://www.google.com https://www.gstatic.com https://service.mtcaptcha.com https://service2.mtcaptcha.com;"
);


// ── CSRF Token ─────────────────────────────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

// ── Rate Limiting (Token Bucket) ──────────────────────────────────────────
if (defined('TRUST_PROXY_HEADERS') && TRUST_PROXY_HEADERS) {
  $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
} else {
  $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}
$ip = explode(',', trim($ip))[0];

$rateLimitDir = __DIR__ . '/data/limits';
if (!is_dir($rateLimitDir)) @mkdir($rateLimitDir, 0750, true);

$ipHash = hash('sha256', (defined('LOG_IP_SALT') ? LOG_IP_SALT : 'fallback') . $ip);
$limitFile = $rateLimitDir . '/limit_' . $ipHash . '.php';

$capacity = RATE_LIMIT_MAX;
$refillRate = $capacity / RATE_LIMIT_WINDOW;
$tokens = $capacity;
$lastUpdate = time();

$rateLimited = false;
$isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');

$fp = @fopen($limitFile, 'c+');
if ($fp) {
  if (flock($fp, LOCK_EX)) {
    $raw = stream_get_contents($fp);
    if (strlen($raw) > 15) {
      $data = json_decode(substr($raw, 15), true);
      if (is_array($data)) {
        $tokens = $data['tokens'] ?? $capacity;
        $lastUpdate = $data['last_update'] ?? time();
      }
    }
    
    $now = time();
    $elapsed = $now - $lastUpdate;
    $tokens += $elapsed * $refillRate;
    if ($tokens > $capacity) $tokens = $capacity;
    
    if ($isPost) {
      if ($tokens >= 1) {
        $tokens -= 1;
        $rateLimited = false;
      } else {
        $rateLimited = true;
      }
    } else {
      $rateLimited = ($tokens < 1);
    }
    
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, "<?php exit; ?>\n" . json_encode([
      'tokens' => $tokens,
      'last_update' => $now
    ]));
    
    flock($fp, LOCK_UN);
  }
  fclose($fp);
}

// ── API Function ───────────────────────────────────────────────────────────
function daCreateUser(array $data): array
{
  $url = DA_HOST . ':' . DA_PORT . '/CMD_API_ACCOUNT_USER';
  $payload = http_build_query(array_merge([
    'action' => 'create',
    'add' => 'Submit',
    'ip' => DA_IP,
    'package' => DA_DEFAULT_PACKAGE,
    'notify' => DA_NOTIFY_USER,
  ], $data));

  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $payload,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_USERPWD => DA_ADMIN_USER . ':' . DA_ADMIN_PASS,
    CURLOPT_SSL_VERIFYPEER => DA_SSL_VERIFY,
    CURLOPT_SSL_VERIFYHOST => DA_SSL_VERIFY ? 2 : 0,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
  ]);
  $response = curl_exec($ch);
  $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $errno = curl_errno($ch);
  $errorMsg = curl_error($ch);
  curl_close($ch);

  if ($errno) {
    return ['success' => false, 'message' => 'Connection to server failed: ' . htmlspecialchars($errorMsg)];
  }

  if ($httpCode === 401) {
    return ['success' => false, 'message' => 'Authentication failed (401). Please check DA_ADMIN_USER (use plain username e.g. "admin", without "|keyname") and DA_ADMIN_PASS (the generated Login Key secret).'];
  }

  if ($httpCode === 403) {
    return ['success' => false, 'message' => 'Access forbidden (403). Your account or Login Key lacks permission for CMD_API_ACCOUNT_USER.'];
  }

  parse_str($response, $parsed);
  if (isset($parsed['error']) && $parsed['error'] === '0') {
    return ['success' => true, 'message' => 'Account successfully created!'];
  }

  if (isset($parsed['details']) && !empty($parsed['details'])) {
    return ['success' => false, 'message' => htmlspecialchars($parsed['details'])];
  }

  if (isset($parsed['text']) && !empty($parsed['text'])) {
    return ['success' => false, 'message' => htmlspecialchars($parsed['text'])];
  }

  // Fallback: If DirectAdmin returns plain text or HTML (e.g. error page)
  $cleanResponse = trim(strip_tags($response));
  if (!empty($cleanResponse)) {
    // Truncate response if too long
    $snippet = (mb_strlen($cleanResponse) > 200) ? mb_substr($cleanResponse, 0, 200) . '...' : $cleanResponse;
    return ['success' => false, 'message' => 'Server error (HTTP ' . $httpCode . '): ' . htmlspecialchars($snippet)];
  }

  return ['success' => false, 'message' => 'Unknown error from server (HTTP ' . $httpCode . ').'];
}

// ── Audit Log ──────────────────────────────────────────────────────────────
/**
 * Writes a GDPR-compliant, JSON-Lines audit entry to the log file.
 * IPs are pseudonymized via a salted SHA-256 hash (not reversible without the salt).
 * Email addresses are masked to protect PII (e.g. j***@gmail.com).
 * The log file is rotated when it exceeds AUDIT_LOG_MAX_SIZE bytes.
 */
function auditLog(string $username, string $email, string $domain, string $result, string $reason): void
{
  if (!defined('AUDIT_LOG_ENABLED') || !AUDIT_LOG_ENABLED) return;

  $logPath = AUDIT_LOG_PATH;
  $logDir  = dirname($logPath);
  if (!is_dir($logDir)) @mkdir($logDir, 0750, true);

  // Rotate if over size limit
  if (file_exists($logPath) && filesize($logPath) > AUDIT_LOG_MAX_SIZE) {
    @rename($logPath, $logPath . '.' . date('Ymd-His'));
  }

  // Pseudonymize IP (GDPR: no plaintext personal data)
  $rawIp  = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
  $anonIp = substr(hash('sha256', $rawIp . LOG_IP_SALT), 0, 16);

  // Mask email (keep first char + domain for debugging)
  $maskedEmail = '';
  if ($email && strpos($email, '@') !== false) {
    [$local, $dom] = explode('@', $email, 2);
    $maskedEmail   = substr($local, 0, 1) . '***@' . $dom;
  }

  $entry = json_encode([
    't'      => date('c'),
    'ip'     => $anonIp,
    'user'   => $username,
    'domain' => $domain,
    'email'  => $maskedEmail,
    'result' => $result,
    'reason' => $reason ?: null,
  ], JSON_UNESCAPED_UNICODE);

  $fp = @fopen($logPath, 'a');
  if ($fp) {
    flock($fp, LOCK_EX);
    if (filesize($logPath) === 0) {
      fwrite($fp, "<?php exit; ?>\n");
    }
    fwrite($fp, $entry . "\n");
    flock($fp, LOCK_UN);
    fclose($fp);
  }
}

// ── DNS MX Check ───────────────────────────────────────────────────────────
/**
 * Checks if a domain has valid MX records.
 * Results are cached in the session for 60s to prevent DNS flooding on retries.
 * Fail-open: returns true if DNS resolution itself fails.
 */
function checkEmailMx(string $domain): bool
{
  if (!defined('ENABLE_MX_CHECK') || !ENABLE_MX_CHECK) return true;
  if (!$domain) return false;

  $cacheKey = 'mx_' . md5($domain);
  if (isset($_SESSION[$cacheKey]) && (time() - $_SESSION[$cacheKey]['ts']) < 60) {
    return $_SESSION[$cacheKey]['result'];
  }

  // checkdnsrr returns false on both "no MX" and "resolution failure"
  // Use dns_get_record for more control; fall back to true on error (fail-open)
  set_error_handler(function() {}, E_WARNING);
  $records = dns_get_record($domain, DNS_MX | DNS_A);
  restore_error_handler();

  // Fail-open: if dns_get_record returns false (DNS unavailable), allow registration
  if ($records === false) {
    $_SESSION[$cacheKey] = ['result' => true, 'ts' => time()];
    return true;
  }

  $hasMx = !empty($records);
  $_SESSION[$cacheKey] = ['result' => $hasMx, 'ts' => time()];
  return $hasMx;
}

// ── Invite Code Validation ─────────────────────────────────────────────────
/**
 * Validates an invite code and marks it as used if INVITE_SINGLE_USE is true.
 * Uses exclusive file locking to prevent race conditions.
 */
function validateInviteCode(string $code): bool
{
  if (!defined('INVITE_ONLY_MODE') || !INVITE_ONLY_MODE) return true;

  $code = strtoupper(preg_replace('/[^A-Z0-9\-]/', '', strtoupper(trim($code))));
  if (!$code) return false;

  // Check against configured valid codes (timing-safe loop)
  $isValid = false;
  foreach (INVITE_CODES as $validCode) {
    if (hash_equals(strtoupper(trim($validCode)), $code)) {
      $isValid = true;
      break;
    }
  }
  if (!$isValid) return false;

  if (!defined('INVITE_SINGLE_USE') || !INVITE_SINGLE_USE) return true;

  // Check and mark as used via flat file with exclusive lock
  $file = INVITE_CODES_FILE;
  $dir  = dirname($file);
  if (!is_dir($dir)) @mkdir($dir, 0750, true);
  if (!file_exists($file)) file_put_contents($file, "<?php exit; ?>\n" . json_encode(['used' => []]));

  $fp = @fopen($file, 'r+');
  if (!$fp) return false; // Cannot acquire file handle → deny

  $result = false;
  if (flock($fp, LOCK_EX)) {
    $raw = stream_get_contents($fp);
    $jsonStr = substr($raw, 15) ?: '{}';
    $data = json_decode($jsonStr, true) ?? ['used' => []];
    if (!in_array($code, (array)($data['used'] ?? []), true)) {
      $data['used'][] = $code;
      rewind($fp);
      ftruncate($fp, 0);
      fwrite($fp, "<?php exit; ?>\n" . json_encode($data, JSON_PRETTY_PRINT));
      $result = true;
    }
    flock($fp, LOCK_UN);
  }
  fclose($fp);
  return $result;
}



/**
 * Sends a POST request to a CAPTCHA verification API and returns decoded JSON.
 */
function captchaCurl(string $url, array $data): array
{
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => http_build_query($data),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_SSL_VERIFYPEER => DA_SSL_VERIFY,
    CURLOPT_SSL_VERIFYHOST => DA_SSL_VERIFY ? 2 : 0,
    CURLOPT_TIMEOUT => 10,
  ]);
  $res = curl_exec($ch);
  curl_close($ch);
  return json_decode((string) $res, true) ?? [];
}

/**
 * Verifies an ALTCHA proof-of-work payload without any external API call.
 * Steps: decode base64-JSON → check algorithm → verify PoW hash → verify HMAC signature → check expiry.
 */
function verifyAltchaPayload(string $payload): bool
{
  if (!$payload)
    return false;
  $data = json_decode(base64_decode($payload), true);
  if (!is_array($data))
    return false;

  $alg = $data['algorithm'] ?? '';
  $challenge = $data['challenge'] ?? '';
  $salt = $data['salt'] ?? '';
  $number = (string) ($data['number'] ?? '');
  $signature = $data['signature'] ?? '';

  // Only SHA-256 is supported
  if ($alg !== 'SHA-256')
    return false;

  // Check expiry embedded in salt params (e.g. "abc123?expires=1234567890")
  $query = parse_url($salt, PHP_URL_QUERY) ?? '';
  parse_str($query, $saltParams);
  if (isset($saltParams['expires']) && time() > (int) $saltParams['expires'])
    return false;

  // Verify Proof-of-Work: hash(salt + number) must equal challenge
  if (hash('sha256', $salt . $number) !== $challenge)
    return false;

  // Verify HMAC signature: prevents crafted challenges
  $expected = hash_hmac('sha256', $challenge, ALTCHA_HMAC_KEY);
  return hash_equals($expected, $signature);
}

/**
 * Dispatches to the configured CAPTCHA provider and returns true on success.
 */
function verifyCaptcha(): bool
{
  $provider = CAPTCHA_PROVIDER;
  if ($provider === 'none')
    return true;

  if ($provider === 'hcaptcha') {
    $token = $_POST['h-captcha-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://api.hcaptcha.com/siteverify', [
      'secret' => HCAPTCHA_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'recaptcha') {
    $token = $_POST['g-recaptcha-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://www.google.com/recaptcha/api/siteverify', [
      'secret' => RECAPTCHA_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'altcha') {
    return verifyAltchaPayload($_POST['altcha'] ?? '');
  }

  if ($provider === 'turnstile') {
    $token = $_POST['cf-turnstile-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
      'secret' => TURNSTILE_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'mtcaptcha') {
    $token = $_POST['mtcaptcha-verifiedtoken'] ?? '';
    if (!$token)
      return false;
    // MTCaptcha uses GET for verification
    $url = 'https://service.mtcaptcha.com/mtcv1/api/checktoken'
      . '?privatekey=' . urlencode(MTCAPTCHA_PRIVATE_KEY)
      . '&token=' . urlencode($token);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_SSL_VERIFYPEER => DA_SSL_VERIFY,
      CURLOPT_SSL_VERIFYHOST => DA_SSL_VERIFY ? 2 : 0,
      CURLOPT_TIMEOUT => 10,
    ]);
    $res = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno || !$res)
      return false;
    $parsed = json_decode($res, true);
    return ($parsed['success'] ?? false) === true;
  }

  return false;
}

// ── Process Form ───────────────────────────────────────────────────────────
$result = null;
if ($rateLimited && $_SERVER['REQUEST_METHOD'] !== 'POST') {
  $result = ['success' => false, 'message' => 'Too many registration attempts. Please wait a few minutes before trying again.'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Honeypot check
  if (!empty($_POST['website_hp'])) {
    // Silently drop bot registration but pretend it succeeded
    $result = ['success' => true, 'message' => 'Account successfully created!'];
  } elseif (!hash_equals($csrf, $_POST['csrf_token'] ?? '')) {
    $result = ['success' => false, 'message' => 'Invalid security token. Please refresh the page.'];
  } elseif ($rateLimited) {
    $result = ['success' => false, 'message' => 'Too many registrations. Please wait a few minutes.'];
  } elseif (CAPTCHA_PROVIDER !== 'none' && !verifyCaptcha()) {
    $result = ['success' => false, 'message' => 'CAPTCHA verification failed. Please try again.'];
  } else {
    $username = strtolower(trim($_POST['username'] ?? ''));
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $domain = trim($_POST['domain'] ?? '');
    $passwd = $_POST['passwd'] ?? '';
    $passwd2 = $_POST['passwd2'] ?? '';
    $emailDomain = $email ? substr(strrchr($email, "@"), 1) : '';

    // Reserved Names Check
    $isReservedDomain = false;
    if (!empty($domain)) {
      $lowerDomain = strtolower($domain);
      $blockSub = defined('BLOCK_RESERVED_SUBDOMAINS') && BLOCK_RESERVED_SUBDOMAINS;
      foreach (RESERVED_DOMAINS as $rd) {
        $lowerRd = strtolower($rd);
        if ($lowerDomain === $lowerRd) {
          $isReservedDomain = true;
          break;
        }
        if ($blockSub && str_ends_with($lowerDomain, '.' . $lowerRd)) {
          $isReservedDomain = true;
          break;
        }
      }
    }

    if (MAINTENANCE_MODE) {
      $result = ['success' => false, 'message' => 'Registrations are currently paused.'];
      auditLog($username ?? '', $email ?: '', $domain ?? '', 'fail', 'maintenance_mode');
    } elseif ((!empty(TOS_URL) || !empty(PRIVACY_URL)) && empty($_POST['tos_agree'])) {
      $result = ['success' => false, 'message' => 'You must agree to the Terms of Service and Privacy Policy.'];
      auditLog($username ?? '', $email ?: '', $domain ?? '', 'fail', 'tos_not_agreed');
    } elseif (INVITE_ONLY_MODE && !validateInviteCode($_POST['invite_code'] ?? '')) {
      $result = ['success' => false, 'message' => 'invite_invalid'];
      auditLog($username ?? '', $email ?: '', $domain ?? '', 'fail', 'invite_invalid');
    } elseif (!preg_match('/^[a-z0-9]{4,8}$/', $username)) {
      $result = ['success' => false, 'message' => 'Username must be 4-8 characters long (a-z, 0-9 only).'];
      auditLog($username, $email ?: '', $domain ?? '', 'fail', 'username_invalid');
    } elseif (in_array(strtolower($username), RESERVED_USERNAMES)) {
      $result = ['success' => false, 'message' => 'This username is reserved and cannot be registered.'];
      auditLog($username, $email ?: '', $domain ?? '', 'fail', 'username_reserved');
    } elseif (!$email) {
      $result = ['success' => false, 'message' => 'Please enter a valid email address.'];
      auditLog($username, '', $domain ?? '', 'fail', 'email_invalid');
    } elseif ($emailDomain && in_array(strtolower($emailDomain), BLOCKED_EMAIL_DOMAINS)) {
      $result = ['success' => false, 'message' => 'This email provider is not allowed. Please use a valid email address.'];
      auditLog($username, $email, $domain ?? '', 'fail', 'email_domain_blocked');
    } elseif ($emailDomain && !checkEmailMx($emailDomain)) {
      $result = ['success' => false, 'message' => 'email_mx_invalid'];
      auditLog($username, $email, $domain ?? '', 'fail', 'email_mx_no_records');
    } elseif (empty($domain) || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || strpos($domain, '.') === false) {
      $result = ['success' => false, 'message' => 'Please enter a valid domain (e.g. example.com).'];
      auditLog($username, $email, $domain ?? '', 'fail', 'domain_invalid');
    } elseif ($isReservedDomain) {
      $result = ['success' => false, 'message' => 'This domain is reserved and cannot be registered.'];
      auditLog($username, $email, $domain, 'fail', 'domain_reserved');
    } elseif (strlen($passwd) < PASSWD_MIN_LENGTH) {
      $result = ['success' => false, 'message' => 'Password must be at least ' . PASSWD_MIN_LENGTH . ' characters long.'];
      auditLog($username, $email, $domain, 'fail', 'password_too_short');
    } elseif (PASSWD_REQUIRE_COMPLEXITY && (!preg_match('/[A-Z]/', $passwd) || !preg_match('/[a-z]/', $passwd) || !preg_match('/[0-9]/', $passwd))) {
      $result = ['success' => false, 'message' => 'Password must contain at least one uppercase letter, one lowercase letter, and one number.'];
      auditLog($username, $email, $domain, 'fail', 'password_complexity');
    } elseif ($passwd !== $passwd2) {
      $result = ['success' => false, 'message' => 'Passwords do not match.'];
      auditLog($username, $email, $domain, 'fail', 'password_mismatch');
    } else {
      $result = daCreateUser([
        'username' => $username,
        'email' => $email,
        'domain' => $domain,
        'passwd' => $passwd,
        'passwd2' => $passwd2,
      ]);

      auditLog($username, $email, $domain, $result['success'] ? 'success' : 'fail', $result['success'] ? '' : 'da_api_error');
      if ($result['success']) {
        if (WEBHOOK_ENABLED && !empty(WEBHOOK_URL)) {
          $payload = json_encode(['content' => "🔔 **New Registration**\nUser: `{$username}`\nDomain: `{$domain}`\nEmail: `{$email}`"]);
          $ch = curl_init(WEBHOOK_URL);
          curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
          curl_setopt($ch, CURLOPT_POST, 1);
          curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
          curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
          curl_setopt($ch, CURLOPT_TIMEOUT, 3);
          curl_exec($ch);
          curl_close($ch);
        }

        if (!empty(ADMIN_EMAIL)) {
          $subject = "New Registration: $username";
          $msg = "A new user has registered.\n\nUsername: $username\nDomain: $domain\nEmail: $email\nDate: " . date('Y-m-d H:i:s') . "\nIP: " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
          $rawHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
          $host = preg_replace('/[^a-zA-Z0-9\.\-]/', '', $rawHost) ?: 'localhost';
          $headers = "From: no-reply@" . $host . "\r\n" .
            "Reply-To: " . filter_var($email, FILTER_SANITIZE_EMAIL) . "\r\n" .
            "X-Mailer: PHP/" . phpversion();
          @mail(ADMIN_EMAIL, $subject, $msg, $headers);
        }
      }
    }
  }
  // Regenerate Token
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
  $csrf = $_SESSION['csrf_token'];
}

$now = date('j.n.Y, H:i');
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title><?= SITE_TITLE ?></title>
  <meta name="description" content="DirectAdmin Account Registration" />
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet" />
  <meta name="googlebot" content="noindex, nofollow" />
  <link rel="icon" type="image/svg+xml"
    href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 42 42'%3E%3Crect width='42' height='42' rx='10' fill='%2300adef'/%3E%3Cpath d='M8 21L16 13L24 21L16 29L8 21Z' fill='%23ffffff'/%3E%3Cpath d='M18 21L26 13L34 21L26 29L18 21Z' fill='%23ffffff' opacity='.6'/%3E%3C/svg%3E" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet" />
  <?php if (CAPTCHA_PROVIDER === 'hcaptcha'): ?>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'recaptcha'): ?>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'altcha'): ?>
    <script type="module" src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js"></script>
  <?php elseif (CAPTCHA_PROVIDER === 'turnstile'): ?>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'mtcaptcha'): ?>
    <script>
      var mtcaptchaConfig = { "sitekey": "<?= htmlspecialchars(MTCAPTCHA_SITE_KEY) ?>" };
      (function () {
        var mt_service = document.createElement('script');
        mt_service.async = true;
        mt_service.src = 'https://service.mtcaptcha.com/mtcv1/client/mtcaptcha.min.js';
        (document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(mt_service);
        var mt_service2 = document.createElement('script');
        mt_service2.async = true;
        mt_service2.src = 'https://service2.mtcaptcha.com/mtcv1/client/mtcaptcha2.min.js';
        (document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(mt_service2);
      })();
    </script>
  <?php endif; ?>
  <style>
    :root {
      --bg: #0f1117;
      --poly: #161b27;
      --card: #1e2430;
      --card-b: rgba(255, 255, 255, .06);
      --input-bg: #252d3d;
      --input-b: rgba(255, 255, 255, .1);
      --input-bh: #00adef;
      --text: #e8ecf4;
      --sub: #8a93a8;
      --btn: #00adef;
      --btn-h: #0098d4;
      --btn-text: #fff;
      --err-bg: rgba(220, 53, 69, .12);
      --err-b: rgba(220, 53, 69, .4);
      --err-text: #ff6b7a;
      --ok-bg: rgba(25, 185, 84, .12);
      --ok-b: rgba(25, 185, 84, .4);
      --ok-text: #2ecc71;
      --time: #5a6478;
      --icon-btn: rgba(255, 255, 255, .08);
      --icon-bth: rgba(255, 255, 255, .16);
      --sb-track: rgba(0, 0, 0, .2);
      --sb-thumb: rgba(255, 255, 255, .2);
      --sb-thumb-h: rgba(255, 255, 255, .35);
    }

    [data-theme="light"] {
      --bg: #5ab4e5;
      --poly: #4fa8d8;
      --card: #ffffff;
      --card-b: rgba(0, 0, 0, .08);
      --input-bg: #f5f7fb;
      --input-b: rgba(0, 0, 0, .12);
      --input-bh: #00adef;
      --text: #1a2233;
      --sub: #5a6a85;
      --btn: #2e86c1;
      --btn-h: #1f6fa3;
      --btn-text: #fff;
      --err-bg: rgba(220, 53, 69, .08);
      --err-b: rgba(220, 53, 69, .3);
      --err-text: #c0392b;
      --ok-bg: rgba(25, 185, 84, .08);
      --ok-b: rgba(25, 185, 84, .3);
      --ok-text: #1a8a44;
      --time: rgba(255, 255, 255, .7);
      --icon-btn: rgba(255, 255, 255, .25);
      --icon-bth: rgba(255, 255, 255, .45);
      --sb-track: rgba(0, 0, 0, .05);
      --sb-thumb: rgba(0, 0, 0, .25);
      --sb-thumb-h: rgba(0, 0, 0, .4);
    }

    *,
    *::before,
    *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0
    }

    * {
      scrollbar-width: thin;
      scrollbar-color: var(--sb-thumb) var(--sb-track)
    }

    ::-webkit-scrollbar {
      width: 8px;
      height: 8px
    }

    ::-webkit-scrollbar-track {
      background: var(--sb-track);
      border-radius: 4px
    }

    ::-webkit-scrollbar-thumb {
      background: var(--sb-thumb);
      border-radius: 4px;
      transition: background .2s
    }

    ::-webkit-scrollbar-thumb:hover {
      background: var(--sb-thumb-h)
    }

    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      transition: background .35s, color .35s;
      position: relative;
      overflow-x: hidden;
      overflow-y: auto;
    }

    /* Preloader */
    #preloader {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: var(--bg);
      z-index: 9999;
      display: grid;
      place-content: center;
      transition: opacity 0.5s ease, visibility 0.5s ease;
    }

    #preloader.hidden {
      opacity: 0;
      visibility: hidden;
    }

    #preloader-spinner {
      color: #00adef;
      display: inline-block;
      position: relative;
      width: 80px;
      height: 80px;
    }

    #preloader-spinner div {
      box-sizing: border-box;
      display: block;
      position: absolute;
      width: 96px;
      height: 96px;
      margin: 8px;
      border: 8px solid currentColor;
      border-radius: 50%;
      animation: lds-ring 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
      border-color: currentColor transparent transparent transparent;
    }

    #preloader-spinner div:nth-child(1) {
      animation-delay: -0.45s;
    }

    #preloader-spinner div:nth-child(2) {
      animation-delay: -0.3s;
    }

    #preloader-spinner div:nth-child(3) {
      animation-delay: -0.15s;
    }

    @keyframes lds-ring {
      0% {
        transform: rotate(0deg);
      }

      100% {
        transform: rotate(360deg);
      }
    }

    /* Polygon-Background */
    .bg-poly {
      position: fixed;
      inset: 0;
      z-index: 0;
      overflow: hidden;
      pointer-events: none;
    }

    .bg-poly svg {
      width: 100%;
      height: 100%;
      opacity: .45
    }

    [data-theme="light"] .bg-poly svg {
      opacity: .3
    }

    /* Top-Right Controls */
    .top-controls {
      position: fixed;
      top: 16px;
      right: 20px;
      display: flex;
      gap: 10px;
      align-items: center;
      z-index: 100;
    }

    .icon-btn {
      width: 36px;
      height: 36px;
      border-radius: 50%;
      background: var(--icon-btn);
      border: 1px solid var(--card-b);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: background .2s;
      color: var(--text);
    }

    .icon-btn:hover {
      background: var(--icon-bth)
    }

    .icon-btn svg {
      width: 18px;
      height: 18px
    }

    /* Language Dropdown */
    .lang-dropdown-wrap {
      position: relative
    }

    .lang-btn {
      display: flex;
      align-items: center;
      gap: 6px;
      background: var(--icon-btn);
      border: 1px solid var(--card-b);
      border-radius: 18px;
      padding: 6px 14px;
      color: var(--text);
      font-family: inherit;
      font-size: .82rem;
      font-weight: 500;
      cursor: pointer;
      transition: background .2s;
    }

    .lang-btn:hover {
      background: var(--icon-bth)
    }

    .lang-btn svg {
      width: 15px;
      height: 15px;
      opacity: .85
    }

    .lang-dropdown {
      position: absolute;
      top: calc(100% + 6px);
      right: 0;
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 12px;
      padding: 6px;
      width: 170px;
      max-height: 260px;
      overflow-y: auto;
      box-shadow: 0 12px 32px rgba(0, 0, 0, .35);
      display: none;
      z-index: 200;
    }

    .lang-dropdown.show {
      display: block
    }

    .lang-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      padding: 7px 10px;
      border: none;
      background: transparent;
      color: var(--text);
      font-family: inherit;
      font-size: .82rem;
      border-radius: 6px;
      cursor: pointer;
      text-align: left;
      transition: background .15s;
    }

    .lang-item:hover {
      background: var(--input-bg)
    }

    .lang-item.active {
      color: var(--btn);
      font-weight: 600
    }

    /* Card */
    .card {
      position: relative;
      z-index: 1;
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 20px;
      padding: 40px 44px 36px;
      width: 100%;
      max-width: 480px;
      box-shadow: 0 24px 64px rgba(0, 0, 0, .4);
      transition: background .35s, border-color .35s, box-shadow .35s;
    }

    [data-theme="light"] .card {
      box-shadow: 0 12px 40px rgba(0, 0, 0, .15)
    }

    /* Logo */
    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
      justify-content: center;
      margin-bottom: 28px
    }

    .logo-icon {
      width: 42px;
      height: 42px
    }

    .logo-text h1 {
      font-size: 1.45rem;
      font-weight: 600;
      letter-spacing: -.02em;
      color: var(--text)
    }

    .logo-text p {
      font-size: .72rem;
      letter-spacing: .22em;
      color: var(--sub);
      text-transform: uppercase;
      margin-top: 1px
    }

    /* Alert */
    .alert {
      border-radius: 10px;
      padding: 12px 14px;
      font-size: .85rem;
      margin-bottom: 20px;
      border: 1px solid;
      line-height: 1.5;
    }

    .alert-error {
      background: var(--err-bg);
      border-color: var(--err-b);
      color: var(--err-text)
    }

    .alert-success {
      background: var(--ok-bg);
      border-color: var(--ok-b);
      color: var(--ok-text)
    }

    .alert a {
      color: inherit;
      font-weight: 600
    }

    /* Form */
    .field {
      margin-bottom: 18px
    }

    label {
      display: block;
      font-size: .82rem;
      font-weight: 500;
      margin-bottom: 6px;
      color: var(--sub)
    }

    .input-wrap {
      position: relative
    }

    input[type=text],
    input[type=email],
    input[type=password] {
      width: 100%;
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      border-radius: 8px;
      color: var(--text);
      font-family: inherit;
      font-size: .9rem;
      padding: 10px 14px;
      outline: none;
      transition: border-color .2s, background .2s;
    }

    input:focus {
      border-color: var(--input-bh)
    }

    input::placeholder {
      color: var(--sub);
      opacity: .7
    }

    .eye-btn {
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      cursor: pointer;
      color: var(--sub);
      display: flex;
      padding: 4px;
      transition: color .2s;
    }

    .eye-btn:hover {
      color: var(--text)
    }

    .eye-btn svg.hide-icon {
      display: none
    }

    .pw-field {
      padding-right: 42px !important
    }

    .copy-pw-btn {
      background: none;
      border: 1px solid var(--input-b);
      border-radius: 6px;
      cursor: pointer;
      color: var(--sub);
      font-size: 0.78rem;
      padding: 4px 10px;
      display: flex;
      align-items: center;
      gap: 5px;
      transition: all .2s;
      white-space: nowrap;
    }

    .copy-pw-btn:hover {
      color: var(--text);
      border-color: var(--btn)
    }

    .copy-pw-btn.copied {
      color: #2ecc71;
      border-color: #2ecc71
    }

    /* Row */
    .field-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px
    }

    /* Submit */
    .btn {
      width: 100%;
      padding: 11px;
      background: var(--btn);
      color: var(--btn-text);
      border: none;
      border-radius: 10px;
      font-family: inherit;
      font-size: .95rem;
      font-weight: 500;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: background .2s, transform .1s, opacity .2s;
      margin-top: 22px;
    }

    .btn:hover {
      background: var(--btn-h)
    }

    .btn:active {
      transform: scale(.98)
    }

    .btn:disabled {
      opacity: .6;
      cursor: not-allowed
    }

    .spinner {
      width: 18px;
      height: 18px;
      border: 2px solid rgba(255, 255, 255, .4);
      border-top-color: #fff;
      border-radius: 50%;
      animation: spin .7s linear infinite;
      display: none;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg)
      }
    }

    /* Password Strength Meter */
    .pw-meter {
      margin-top: 10px;
    }

    .pw-meter-bar {
      height: 4px;
      background: var(--input-bg);
      border-radius: 2px;
      overflow: hidden;
      border: 1px solid var(--input-b);
    }

    .pw-meter-fill {
      height: 100%;
      width: 0%;
      transition: width 0.3s ease, background-color 0.3s ease;
    }

    .pw-meter-text {
      font-size: 0.75rem;
      margin-top: 4px;
      color: var(--sub);
      display: flex;
      justify-content: space-between;
    }

    /* Password Checklist */
    .pw-checklist {
      list-style: none;
      margin-top: 10px;
      padding: 0;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px 10px;
    }
    .pw-check-item {
      display: flex;
      align-items: center;
      gap: 5px;
      font-size: 0.74rem;
      color: var(--sub);
      transition: color 0.2s;
    }
    .pw-check-item .check-icon {
      width: 15px; height: 15px;
      border-radius: 50%;
      border: 1.5px solid var(--sub);
      display: flex; align-items: center; justify-content: center;
      flex-shrink: 0;
      transition: background 0.2s, border-color 0.2s;
      font-size: 0.65rem;
    }
    .pw-check-item.ok { color: var(--ok-text); }
    .pw-check-item.ok .check-icon {
      background: var(--ok-text);
      border-color: var(--ok-text);
      color: #fff;
    }

    /* HIBP Status */
    .hibp-status {
      font-size: 0.78rem;
      margin-top: 8px;
      padding: 6px 10px;
      border-radius: 6px;
      display: none;
    }
    .hibp-status.checking { display:block; color: var(--sub); }
    .hibp-status.warning  { display:block; color: var(--err-text); background: var(--err-bg); border: 1px solid var(--err-b); }
    .hibp-status.ok       { display:block; color: var(--ok-text); background: var(--ok-bg); border: 1px solid var(--ok-b); }


    .help-fab-wrap {
      position: fixed;
      bottom: 20px;
      left: 20px;
      z-index: 100;
    }

    .help-fab {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--icon-btn);
      border: 1px solid var(--card-b);
      border-radius: 20px;
      padding: 8px 16px;
      color: var(--text);
      font-family: inherit;
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.2s;
    }

    .help-fab:hover {
      background: var(--icon-bth);
    }

    .help-fab svg {
      color: var(--btn);
    }

    .help-menu {
      position: absolute;
      bottom: calc(100% + 10px);
      left: 0;
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 12px;
      padding: 6px;
      width: 180px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, .35);
      display: none;
      flex-direction: column;
      z-index: 200;
    }

    .help-menu.show {
      display: flex;
      animation: fadeIn 0.2s ease-out;
    }

    .help-menu a {
      padding: 8px 12px;
      color: var(--text);
      text-decoration: none;
      font-size: 0.85rem;
      border-radius: 6px;
      transition: background 0.15s;
    }

    .help-menu a:hover {
      background: var(--input-bg);
    }

    /* Bottom time */
    .bottom-time {
      position: fixed;
      bottom: 18px;
      font-size: .78rem;
      color: var(--time);
      z-index: 1;
      transition: color .35s;
    }

    .login-link {
      text-align: center;
      margin-top: 16px;
      font-size: .82rem;
      color: var(--sub)
    }

    .login-link a {
      color: var(--btn);
      text-decoration: none;
      font-weight: 500
    }

    .login-link a:hover {
      text-decoration: underline
    }

    /* ALTCHA Widget Theming */
    altcha-widget {
      --altcha-color-border: var(--input-b);
      --altcha-color-border-focus: var(--input-bh);
      --altcha-color-background: var(--input-bg);
      --altcha-color-text: var(--text);
      --altcha-color-text-secondary: var(--sub);
      --altcha-border-radius: 8px;
      width: 100%;
      margin-top: 18px;
      display: block;
    }

    /* ── Cookie Banner ──────────────────────────────────────────────────────── */
    #cookieBanner {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      z-index: 9998;
      background: rgba(15, 17, 23, 0.96);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-top: 1px solid rgba(0, 173, 239, 0.25);
      padding: 16px 24px;
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
      justify-content: space-between;
      transform: translateY(100%);
      transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }

    #cookieBanner.visible {
      transform: translateY(0);
    }

    [data-theme="light"] #cookieBanner {
      background: rgba(255, 255, 255, 0.96);
      border-top: 1px solid rgba(0, 173, 239, 0.3);
    }

    #cookieBanner p {
      font-size: 0.83rem;
      color: var(--sub);
      line-height: 1.5;
      margin: 0;
      flex: 1;
      min-width: 200px;
    }

    #cookieAcceptBtn {
      background: var(--btn);
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 9px 22px;
      font-family: inherit;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s, transform 0.1s;
      white-space: nowrap;
      flex-shrink: 0;
    }

    #cookieAcceptBtn:hover {
      background: var(--btn-h);
    }

    #cookieAcceptBtn:active {
      transform: scale(0.97);
    }

    /* ── Accessibility Widget ───────────────────────────────────────────────── */
    #a11yWidget {
      position: fixed;
      bottom: 20px;
      right: 20px;
      z-index: 500;
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 8px;
    }

    #a11yToggleBtn {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background: var(--btn);
      border: none;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      box-shadow: 0 4px 16px rgba(0, 173, 239, 0.4);
      transition: background 0.2s, transform 0.2s, box-shadow 0.2s;
    }

    #a11yToggleBtn:hover {
      background: var(--btn-h);
      transform: scale(1.08);
      box-shadow: 0 6px 20px rgba(0, 173, 239, 0.55);
    }

    #a11yToggleBtn svg {
      width: 20px;
      height: 20px;
    }

    #a11yPanel {
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 14px;
      padding: 14px 16px;
      width: 210px;
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.35);
      display: none;
      flex-direction: column;
      gap: 10px;
      animation: fadeIn 0.2s ease-out;
    }

    #a11yPanel.open {
      display: flex;
    }

    #a11yPanel h4 {
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--sub);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin: 0 0 4px;
      border-bottom: 1px solid var(--card-b);
      padding-bottom: 8px;
    }

    .a11y-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .a11y-label {
      font-size: 0.82rem;
      color: var(--text);
    }

    .a11y-controls {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .a11y-btn {
      width: 28px;
      height: 28px;
      border-radius: 6px;
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      color: var(--text);
      font-size: 0.9rem;
      font-family: inherit;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: background 0.15s;
    }

    .a11y-btn:hover {
      background: var(--icon-bth);
    }

    .a11y-toggle-switch {
      position: relative;
      width: 36px;
      height: 20px;
      cursor: pointer;
    }

    .a11y-toggle-switch input {
      opacity: 0;
      width: 0;
      height: 0;
      position: absolute;
    }

    .a11y-slider {
      position: absolute;
      inset: 0;
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      border-radius: 10px;
      transition: background 0.2s;
    }

    .a11y-slider::before {
      content: '';
      position: absolute;
      width: 14px;
      height: 14px;
      left: 2px;
      top: 2px;
      background: var(--sub);
      border-radius: 50%;
      transition: transform 0.2s, background 0.2s;
    }

    .a11y-toggle-switch input:checked + .a11y-slider {
      background: var(--btn);
      border-color: var(--btn);
    }

    .a11y-toggle-switch input:checked + .a11y-slider::before {
      transform: translateX(16px);
      background: #fff;
    }

    #a11yFontSize {
      font-size: 0.78rem;
      color: var(--sub);
      min-width: 22px;
      text-align: center;
    }
  </style>
</head>

<body>

  <!-- Preloader -->
  <div id="preloader">
    <div id="preloader-spinner">
      <div></div>
      <div></div>
      <div></div>
    </div>
  </div>

  <!-- Polygon Background -->
  <div class="bg-poly" aria-hidden="true">
    <svg viewBox="0 0 1440 900" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
      <defs>
        <linearGradient id="g1" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#1a2744" />
          <stop offset="100%" stop-color="#0a0f1e" />
        </linearGradient>
      </defs>
      <polygon points="0,0 480,0 240,300" fill="#1a2744" opacity=".6" />
      <polygon points="480,0 960,0 720,240" fill="#162038" opacity=".5" />
      <polygon points="960,0 1440,0 1200,200" fill="#0d1525" opacity=".7" />
      <polygon points="0,300 240,300 0,600" fill="#111a2e" opacity=".5" />
      <polygon points="240,300 600,150 480,450" fill="#1c2940" opacity=".4" />
      <polygon points="600,150 960,0 720,240" fill="#162038" opacity=".4" />
      <polygon points="1200,200 1440,0 1440,400" fill="#0e1826" opacity=".6" />
      <polygon points="0,600 0,900 300,900" fill="#141f33" opacity=".5" />
      <polygon points="300,900 600,700 900,900" fill="#0d1828" opacity=".4" />
      <polygon points="900,900 1440,700 1440,900" fill="#111c30" opacity=".6" />
      <polygon points="600,700 900,500 1200,700" fill="#172240" opacity=".35" />
      <polygon points="0,600 300,900 600,700 480,450" fill="#0f1a2e" opacity=".3" />
      <polygon points="1200,200 1440,400 1200,700 900,500" fill="#0c1622" opacity=".4" />
    </svg>
  </div>

  <!-- Theme Toggle & Language Selector -->
  <div class="top-controls" role="toolbar" aria-label="Settings">
    <button class="icon-btn" id="themeToggle" aria-label="Toggle theme" title="Light/Dark Mode">
      <!-- Sun icon (light) -->
      <svg id="iconSun" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"
        stroke-width="2" style="display:none">
        <circle cx="12" cy="12" r="4" />
        <path
          d="M12 2v2m0 16v2M4.22 4.22l1.42 1.42m12.72 12.72 1.42 1.42M2 12h2m16 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
      </svg>
      <!-- Moon icon (dark) -->
      <svg id="iconMoon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"
        stroke-width="2">
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
      </svg>
    </button>

    <div class="lang-dropdown-wrap" id="langWrap">
      <button type="button" class="lang-btn" id="langBtn" aria-label="Select language" aria-expanded="false">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10" />
          <path
            d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
        <span id="currentLangLabel">English</span>
      </button>
      <div class="lang-dropdown" id="langDropdown" role="menu"></div>
    </div>
  </div>

  <!-- Card -->
  <div class="card">
    <!-- Logo -->
    <div class="logo">
      <svg class="logo-icon" viewBox="0 0 42 42" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="42" height="42" rx="10" fill="#00adef" opacity=".15" />
        <path d="M8 21L16 13L24 21L16 29L8 21Z" fill="#00adef" />
        <path d="M18 21L26 13L34 21L26 29L18 21Z" fill="#00adef" opacity=".6" />
      </svg>
      <div class="logo-text">
        <h1><?= htmlspecialchars(CARD_HEADING) ?></h1>
        <p data-i18n="subtitle"><?= htmlspecialchars(CARD_SUBHEADING) ?></p>
      </div>
    </div>

    <?php if (MAINTENANCE_MODE): ?>
      <div style="text-align:center; padding: 40px 10px 20px;">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--sub)" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:20px; display:inline-block;">
          <path
            d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z">
          </path>
        </svg>
        <h2 style="margin-bottom:12px; font-weight:600; font-size:1.5rem; color:var(--text);"
          data-i18n="maintenance_heading">Maintenance Mode</h2>
        <p style="color:var(--sub); margin-bottom:20px; font-size: 1rem; line-height:1.5;" data-i18n="maintenance_text">
          New registrations are currently paused for maintenance. Please check back later.
        </p>
      </div>
    <?php elseif ($result && $result['success']): ?>
      <div style="text-align:center; padding: 30px 10px 10px; animation: fadeIn 0.4s ease-out;">
        <svg width="72" height="72" viewBox="0 0 24 24" fill="none" stroke="var(--ok-text)" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:20px; display:inline-block;">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
        <h2 style="margin-bottom:12px; font-weight:600; font-size:1.6rem; color:var(--text);" data-i18n="success_heading">
          Account Created!</h2>
        <p style="color:var(--sub); margin-bottom:15px; font-size: 1rem; line-height:1.5;">
          <?= htmlspecialchars($result['message']) ?>
        </p>
        <div
          style="background: rgba(46, 204, 113, 0.1); border: 1px solid rgba(46, 204, 113, 0.3); border-radius: 8px; padding: 12px; margin-bottom: 25px;">
          <p style="color: var(--ok-text); font-size: 0.85rem; margin: 0; line-height: 1.4;" data-i18n="setup_2fa">
            We recommend enabling Two-Factor Authentication (2FA) in the panel.
          </p>
        </div>
        <a href="<?= htmlspecialchars(PANEL_URL) ?>" class="btn"
          style="text-decoration:none; display:inline-flex; width:auto; padding:0 32px;" data-i18n="to_login">To Login</a>
      </div>
    <?php else: ?>
      <?php if ($result && !$result['success']): ?>
        <div class="alert alert-error">
          <?= htmlspecialchars($result['message']) ?>
        </div>
      <?php endif; ?>

      <form method="POST" action="" id="regForm" novalidate autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>" />
        <input type="text" name="website_hp" style="display:none" tabindex="-1" autocomplete="off">

        <div class="field">
          <label for="username" data-i18n="username">Username</label>
          <input type="text" id="username" name="username" data-i18n-ph="username_ph" placeholder="4–8 chars, a-z 0-9"
            value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" maxlength="8" autocomplete="username" required>
        </div>

        <div class="field">
          <label for="email" data-i18n="email">Email Address</label>
          <input type="email" id="email" name="email" data-i18n-ph="email_ph" placeholder="user@example.com"
            value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" autocomplete="email" required>
          <div id="emailSuggestion" style="display:none; font-size: 0.85rem; margin-top: 6px; color: var(--sub);">
            <span data-i18n="did_you_mean">Did you mean</span> <a href="#" id="emailSuggestionLink"
              style="color: var(--btn); text-decoration: none; font-weight: 500;"></a>?
          </div>
        </div>

        <div class="field">
          <label for="domain" data-i18n="domain">Domain</label>
          <input type="text" id="domain" name="domain" data-i18n-ph="domain_ph" placeholder="example.com"
            value="<?= htmlspecialchars($_POST['domain'] ?? '') ?>" autocomplete="off" required>
        </div>

        <div class="field-row">
          <div class="field" style="margin-bottom:0">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
              <label for="passwd" data-i18n="password" style="margin-bottom:0;">Password</label>
              <button type="button" id="generatePwBtn"
                style="background:none; border:none; cursor:pointer; color:var(--btn); font-size:0.75rem; display:flex; align-items:center; gap:4px; padding:0;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                  stroke-linecap="round" stroke-linejoin="round">
                  <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                </svg>
                <span data-i18n="generate">Generate</span>
              </button>
            </div>
            <div class="input-wrap">
              <input type="password" id="passwd" name="passwd" class="pw-field" data-i18n-ph="password_ph"
                placeholder="Min. <?= PASSWD_MIN_LENGTH ?> chars" autocomplete="new-password" required>
              <button type="button" class="eye-btn" data-target="passwd" aria-label="Show password">
                <!-- Eye open (default: password hidden) -->
                <svg class="show-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                <!-- Eye closed (shown when password is visible) -->
                <svg class="hide-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="display:none">
                  <path
                    d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              </button>
            </div>
          </div>
          <div class="field" style="margin-bottom:0">
            <label for="passwd2" data-i18n="confirm">Confirm</label>
            <div class="input-wrap">
              <input type="password" id="passwd2" name="passwd2" class="pw-field" data-i18n-ph="confirm_ph"
                placeholder="Repeat" autocomplete="new-password" required>
              <button type="button" class="eye-btn" data-target="passwd2" aria-label="Show password">
                <svg class="show-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                <svg class="hide-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="display:none">
                  <path
                    d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        <div class="pw-meter" id="pwMeter">
          <div class="pw-meter-bar">
            <div class="pw-meter-fill" id="pwMeterFill"></div>
          </div>
          <div class="pw-meter-text">
            <span id="pwHint" data-i18n="pw_hint">A-Z, a-z, 0-9</span>
            <div style="display:flex; align-items:center; gap:10px;">
              <span id="pwMeterText"></span>
              <button type="button" id="copyPwBtn" class="copy-pw-btn" style="display:none;" title="Copy password">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                  stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
                <span id="copyPwLabel" data-i18n="copy_pw">Copy</span>
              </button>
            </div>
          </div>
        </div>

        <?php if (defined('PASSWD_SHOW_CHECKLIST') && PASSWD_SHOW_CHECKLIST): ?>
        <ul class="pw-checklist" id="pwChecklist"
            data-min="<?= PASSWD_MIN_LENGTH ?>"
            data-complexity="<?= PASSWD_REQUIRE_COMPLEXITY ? '1' : '0' ?>">
          <li class="pw-check-item" id="chk-length">
            <span class="check-icon">✓</span>
            <span data-i18n-min="pw_req_length">At least <?= PASSWD_MIN_LENGTH ?> characters</span>
          </li>
          <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
          <li class="pw-check-item" id="chk-upper">
            <span class="check-icon">✓</span>
            <span data-i18n="pw_req_upper">One uppercase letter (A-Z)</span>
          </li>
          <li class="pw-check-item" id="chk-lower">
            <span class="check-icon">✓</span>
            <span data-i18n="pw_req_lower">One lowercase letter (a-z)</span>
          </li>
          <li class="pw-check-item" id="chk-number">
            <span class="check-icon">✓</span>
            <span data-i18n="pw_req_number">One number (0-9)</span>
          </li>
          <?php endif; ?>
        </ul>
        <?php endif; ?>

        <?php if (defined('ENABLE_HIBP_CHECK') && ENABLE_HIBP_CHECK): ?>
        <div class="hibp-status" id="hibpStatus"></div>
        <?php endif; ?>

        <?php if (defined('INVITE_ONLY_MODE') && INVITE_ONLY_MODE): ?>
          <div class="field">
            <label for="invite_code" data-i18n="invite_code">Invitation Code</label>
            <input type="text" id="invite_code" name="invite_code"
                   data-i18n-ph="invite_code_ph" placeholder="Enter your invite code"
                   maxlength="32" autocomplete="off" spellcheck="false"
                   style="text-transform:uppercase; letter-spacing:0.05em;">
          </div>
        <?php endif; ?>

        <?php if (!empty(TOS_URL) || !empty(PRIVACY_URL)): ?>
          <div class="field" style="margin-top: 15px; display: flex; align-items: flex-start; gap: 8px;">
            <input type="checkbox" id="tos_agree" name="tos_agree" value="1" required
              style="margin-top: 3px; cursor: pointer; width: auto;">
            <label for="tos_agree"
              style="font-size: 0.85rem; color: var(--sub); line-height: 1.4; font-weight: normal; cursor: pointer;">
              <span data-i18n="tos_prefix">I agree to the</span>
              <?php if (!empty(TOS_URL)): ?>
                <a href="<?= htmlspecialchars(TOS_URL) ?>" target="_blank" data-i18n="tos_link"
                  style="color: var(--btn);">Terms of Service</a>
              <?php endif; ?>
              <?php if (!empty(TOS_URL) && !empty(PRIVACY_URL)): ?>
                <span data-i18n="tos_and">and</span>
              <?php endif; ?>
              <?php if (!empty(PRIVACY_URL)): ?>
                <a href="<?= htmlspecialchars(PRIVACY_URL) ?>" target="_blank" data-i18n="privacy_link"
                  style="color: var(--btn);">Privacy Policy</a>
              <?php endif; ?>
            </label>
          </div>
        <?php endif; ?>

        <div class="captcha-wrapper" style="margin-top: 18px; display: flex; justify-content: center; width: 100%;">
          <?php if (CAPTCHA_PROVIDER === 'hcaptcha'): ?>
            <div class="h-captcha" data-sitekey="<?= htmlspecialchars(HCAPTCHA_SITE_KEY) ?>"></div>
          <?php elseif (CAPTCHA_PROVIDER === 'recaptcha'): ?>
            <div class="g-recaptcha" data-sitekey="<?= htmlspecialchars(RECAPTCHA_SITE_KEY) ?>"></div>
          <?php elseif (CAPTCHA_PROVIDER === 'altcha'): ?>
            <altcha-widget challengeurl="altcha-challenge.php"></altcha-widget>
          <?php elseif (CAPTCHA_PROVIDER === 'turnstile'): ?>
            <div class="cf-turnstile" data-sitekey="<?= htmlspecialchars(TURNSTILE_SITE_KEY) ?>"
              <?= $rateLimited ? 'data-execution="execute"' : '' ?>></div>
          <?php elseif (CAPTCHA_PROVIDER === 'mtcaptcha'): ?>
            <div class="mtcaptcha"></div>
          <?php endif; ?>
        </div>

        <button type="submit" class="btn" id="submitBtn" <?= $rateLimited ? 'disabled' : '' ?>>
          <div class="spinner" id="spinner"></div>
          <span id="submitLabel" data-i18n="register">Register</span>
        </button>
      </form>

      <p class="login-link">
        <span data-i18n="already_registered">Already registered?</span> <a href="<?= htmlspecialchars(PANEL_URL) ?>"
          target="_blank" data-i18n="to_login">To Login</a>
      </p>
    <?php endif; ?>
  </div>

  <div class="bottom-time" id="clock"><?= htmlspecialchars($now) ?></div>

  <?php if (defined('COOKIE_BANNER_ENABLED') && COOKIE_BANNER_ENABLED): ?>
  <!-- Cookie Consent Banner -->
  <div id="cookieBanner" role="dialog" aria-label="Cookie consent" aria-live="polite">
    <p id="cookieBannerText"><?= htmlspecialchars(COOKIE_BANNER_TEXT) ?></p>
    <button id="cookieAcceptBtn" type="button"><?= htmlspecialchars(COOKIE_BANNER_BTN) ?></button>
  </div>
  <?php endif; ?>

  <?php if (defined('ACCESSIBILITY_WIDGET_ENABLED') && ACCESSIBILITY_WIDGET_ENABLED): ?>
  <!-- Accessibility Widget -->
  <div id="a11yWidget" role="complementary" aria-label="Accessibility tools">
    <div id="a11yPanel" role="region" aria-label="Accessibility options">
      <h4>Accessibility</h4>
      <div class="a11y-row">
        <span class="a11y-label">Font Size</span>
        <div class="a11y-controls">
          <button class="a11y-btn" id="a11yFontDec" aria-label="Decrease font size" title="Decrease font size">A−</button>
          <span id="a11yFontSize">100%</span>
          <button class="a11y-btn" id="a11yFontInc" aria-label="Increase font size" title="Increase font size">A+</button>
        </div>
      </div>
      <div class="a11y-row">
        <span class="a11y-label">High Contrast</span>
        <label class="a11y-toggle-switch" aria-label="Toggle high contrast">
          <input type="checkbox" id="a11yContrast">
          <span class="a11y-slider"></span>
        </label>
      </div>
      <div class="a11y-row">
        <span class="a11y-label">Grayscale</span>
        <label class="a11y-toggle-switch" aria-label="Toggle grayscale">
          <input type="checkbox" id="a11yGrayscale">
          <span class="a11y-slider"></span>
        </label>
      </div>
      <div class="a11y-row">
        <span class="a11y-label">Reduce Motion</span>
        <label class="a11y-toggle-switch" aria-label="Toggle reduce motion">
          <input type="checkbox" id="a11yMotion">
          <span class="a11y-slider"></span>
        </label>
      </div>
    </div>
    <button id="a11yToggleBtn" aria-label="Open accessibility tools" aria-expanded="false" aria-controls="a11yPanel">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <path d="M12 8v4l2 2"/>
        <circle cx="12" cy="7" r="1" fill="currentColor" stroke="none"/>
        <path d="M9 17l1.5-4.5M15 17l-1.5-4.5M9 12.5h6"/>
      </svg>
    </button>
  </div>
  <?php endif; ?>

  <?php if (!empty(SUPPORT_EMAIL) || !empty(SUPPORT_URL)): ?>
    <div class="help-fab-wrap" id="helpFabWrap">
      <button class="help-fab" type="button" id="helpFabBtn">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path>
          <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
        <span data-i18n="need_help">Need help?</span>
      </button>
      <div class="help-menu" id="helpMenu">
        <a href="<?= !empty(SUPPORT_URL) ? htmlspecialchars(SUPPORT_URL) : 'mailto:' . htmlspecialchars(SUPPORT_EMAIL) ?>"
          target="_blank" data-i18n="contact_support">Contact Support</a>
        <a href="<?php
            $resetMail = !empty(SUPPORT_RESET_EMAIL) ? SUPPORT_RESET_EMAIL : SUPPORT_EMAIL;
            echo 'mailto:' . htmlspecialchars($resetMail)
                . '?subject=' . rawurlencode('Password Reset Request')
                . '&body=' . rawurlencode("Hello,\n\nI would like to request a password reset for my account.\n\nUsername: \nRegistered domain: \n\nThank you.");
          ?>" data-i18n="forgot_password">Forgot Password?</a>
      </div>
    </div>
  <?php endif; ?>

  <script>
    // ── Theme Toggle ──────────────────────────────────────────────────────────
    const html = document.documentElement;
    const themeBtn = document.getElementById('themeToggle');
    const iconSun = document.getElementById('iconSun');
    const iconMoon = document.getElementById('iconMoon');

    function applyTheme(t) {
      html.setAttribute('data-theme', t);
      iconSun.style.display = (t === 'dark') ? 'block' : 'none';
      iconMoon.style.display = (t === 'light') ? 'block' : 'none';
      localStorage.setItem('da_theme', t);
    }
    let initTheme = localStorage.getItem('da_theme');
    if (!initTheme) {
      initTheme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    applyTheme(initTheme || 'dark');
    themeBtn.addEventListener('click', () => {
      applyTheme(html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });

    // ── Password Strength Meter ───────────────────────────────────────────────
    const pwInput = document.getElementById('passwd');
    const pwMeterFill = document.getElementById('pwMeterFill');
    const pwMeterText = document.getElementById('pwMeterText');

    if (pwInput) {
      pwInput.addEventListener('input', function () {
        const val = this.value;
        if (!val) {
          pwMeterFill.style.width = '0%';
          pwMeterText.textContent = '';
          return;
        }
        let score = 0;
        if (val.length >= <?= PASSWD_MIN_LENGTH ?>) score++;
        if (/[A-Z]/.test(val)) score++;
        if (/[a-z]/.test(val)) score++;
        if (/[0-9]/.test(val)) score++;
        if (/[^A-Za-z0-9]/.test(val)) score++;

        const langCode = localStorage.getItem('da_lang') || 'en';
        const curDict = I18N[langCode] || I18N['en'];
        let width = '25%', color = '#ff4d4d', label = curDict.pw_weak || 'Weak';
        if (score >= 4) {
          width = '100%'; color = '#2ecc71'; label = curDict.pw_strong || 'Strong';
        } else if (score >= 3) {
          width = '66%'; color = '#ffa64d'; label = curDict.pw_medium || 'Medium';
        } else if (score >= 2) {
          width = '33%'; color = '#ff4d4d'; label = curDict.pw_weak || 'Weak';
        }

        pwMeterFill.style.width = width;
        pwMeterFill.style.backgroundColor = color;
        pwMeterText.textContent = label;
        pwMeterText.style.color = color;
      });
    }

    // ── Multi-Language (i18n) Engine ───────────────────────────────────────────
    const I18N = {
      en: { name: 'English', subtitle: 'web control panel', username: 'Username', username_ph: '4\u20138 chars, a-z 0-9', email: 'Email Address', email_ph: 'user@example.com', domain: 'Domain', domain_ph: 'example.com', password: 'Password', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> chars', confirm: 'Confirm', confirm_ph: 'Repeat', register: 'Register', already_registered: 'Already registered?', to_login: 'To Login', to_panel: 'To Panel', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Weak', pw_medium: 'Medium', pw_strong: 'Strong', please_wait: 'Please wait...', success_heading: 'Account Created!', generate: 'Generate', maintenance_heading: 'Maintenance Mode', maintenance_text: 'New registrations are currently paused for maintenance. Please check back later.', tos_prefix: 'I agree to the', tos_link: 'Terms of Service', tos_and: 'and', privacy_link: 'Privacy Policy', did_you_mean: 'Did you mean', setup_2fa: 'We recommend enabling Two-Factor Authentication (2FA) in the panel.', copy_pw: 'Copy', need_help: 'Need help?', contact_support: 'Contact Support', forgot_password: 'Forgot Password?', pw_req_length: 'At least {n} characters', pw_req_upper: 'One uppercase letter (A-Z)', pw_req_lower: 'One lowercase letter (a-z)', pw_req_number: 'One number (0-9)', email_mx_invalid: 'The email domain does not appear to accept mail.', pw_hibp_warning: '⚠️ This password appeared in {n} data breach(es).', pw_hibp_ok: '✓ Password not found in known data breaches.', pw_hibp_checking: 'Checking password security...', invite_code: 'Invitation Code', invite_code_ph: 'Enter your invite code', invite_required: 'An invitation code is required to register.', invite_invalid: 'Invalid or already used invitation code.' },
      cs: { name: '\u010ce\u0161tina', subtitle: 'webov\u00fd ovl\u00e1dac\u00ed panel', username: 'U\u017eivatelsk\u00e9 jm\u00e9no', username_ph: '4\u20138 znak\u016f, a-z 0-9', email: 'E-mailov\u00e1 adresa', email_ph: 'uzivatel@priklad.cz', domain: 'Dom\u00e9na', domain_ph: 'priklad.cz', password: 'Heslo', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> znak\u016f', confirm: 'Potvrdit', confirm_ph: 'Opakovat', register: 'Registrovat', already_registered: 'Ji\u017e m\u00e1te \u00fa\u010det?', to_login: 'P\u0159ihl\u00e1sit se', to_panel: 'Do panelu', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Slab\u00e9', pw_medium: 'St\u0159edn\u00ed', pw_strong: 'Siln\u00e9', please_wait: '\u010cekejte pros\u00edm...', success_heading: '\u00da\u010det byl vytvo\u0159en!', generate: 'Generovat', maintenance_heading: 'Re\u017eim \u00fadr\u017eby', maintenance_text: 'Nov\u00e9 registrace jsou z d\u016fvodu \u00fadr\u017eby pozastaveny. Zkuste to pros\u00edm pozd\u011bji.', tos_prefix: 'Souhlas\u00edm s', tos_link: 'obchodn\u00edmi podm\u00ednkami', tos_and: 'a', privacy_link: 'z\u00e1sadami ochrany osobn\u00fdch \u00fadaj\u016f', did_you_mean: 'M\u011bli jste na mysli', setup_2fa: 'Doporu\u010dujeme v panelu zapnout dvoj\u00fazov\u00e9 ov\u011b\u0159en\u00ed (2FA).', copy_pw: 'Kop\u00edrovat', need_help: 'Potřebujete pomoc?', contact_support: 'Kontaktovat podporu', forgot_password: 'Zapomenuté heslo?', pw_req_length: 'Alespoň {n} znaků', pw_req_upper: 'Jedno velké písmeno (A-Z)', pw_req_lower: 'Jedno malé písmeno (a-z)', pw_req_number: 'Jedna číslice (0-9)', email_mx_invalid: 'Zdá se, že doména e-mailu nepřijímá poštu.', pw_hibp_warning: '⚠️ Toto heslo se objevilo v {n} úniku dat.', pw_hibp_ok: '✓ Heslo nebylo nalezeno ve známých únicích dat.', pw_hibp_checking: 'Kontrola bezpečnosti hesla...', invite_code: 'Zvací kód', invite_code_ph: 'Zadejte svůj zvací kód', invite_required: 'K registraci je vyžadován zvací kód.', invite_invalid: 'Neplatný nebo již použitý zvací kód.' },
      de: { name: 'Deutsch', subtitle: 'Web-Control-Panel', username: 'Benutzername', username_ph: '4\u20138 Zeichen, a-z 0-9', email: 'E-Mail-Adresse', email_ph: 'user@example.com', domain: 'Domain', domain_ph: 'beispiel.de', password: 'Passwort', password_ph: 'Mind. <?= PASSWD_MIN_LENGTH ?> Zeichen', confirm: 'Best\u00e4tigen', confirm_ph: 'Wiederholen', register: 'Registrieren', already_registered: 'Bereits registriert?', to_login: 'Zum Login', to_panel: 'Zum Panel', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Schwach', pw_medium: 'Mittel', pw_strong: 'Stark', please_wait: 'Bitte warten...', success_heading: 'Konto erstellt!', generate: 'Generieren', maintenance_heading: 'Wartungsmodus', maintenance_text: 'Neue Registrierungen sind wegen Wartungsarbeiten derzeit pausiert. Bitte versuchen Sie es sp\u00e4ter erneut.', tos_prefix: 'Ich stimme den', tos_link: 'AGB', tos_and: 'und der', privacy_link: 'Datenschutzerkl\u00e4rung zu', did_you_mean: 'Meinten Sie', setup_2fa: 'Wir empfehlen, im Panel die Zwei-Faktor-Authentifizierung (2FA) zu aktivieren.', copy_pw: 'Kopieren', need_help: 'Brauchen Sie Hilfe?', contact_support: 'Support kontaktieren', forgot_password: 'Passwort vergessen?', pw_req_length: 'Mind. {n} Zeichen', pw_req_upper: 'Ein Großbuchstabe (A-Z)', pw_req_lower: 'Ein Kleinbuchstabe (a-z)', pw_req_number: 'Eine Zahl (0-9)', email_mx_invalid: 'Die E-Mail-Domain hat keine Mailserver.', pw_hibp_warning: '⚠️ Dieses Passwort taucht in {n} Datenleck(s) auf.', pw_hibp_ok: '✓ Passwort nicht in bekannten Datenlecks gefunden.', pw_hibp_checking: 'Passwortsicherheit wird geprüft...', invite_code: 'Einladungscode', invite_code_ph: 'Code eingeben', invite_required: 'Zur Registrierung ist ein Einladungscode erforderlich.', invite_invalid: 'Ungültiger oder bereits verwendeter Einladungscode.' },
      fr: { name: 'Fran\u00e7ais', subtitle: 'panneau de contr\u00f4le web', username: 'Nom d\'utilisateur', username_ph: '4\u20138 caract., a-z 0-9', email: 'Adresse e-mail', email_ph: 'user@example.com', domain: 'Domaine', domain_ph: 'exemple.com', password: 'Mot de passe', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> caract.', confirm: 'Confirmer', confirm_ph: 'R\u00e9p\u00e9ter', register: 'S\'inscrire', already_registered: 'D\u00e9j\u00e0 inscrit ?', to_login: 'Connexion', to_panel: 'Au panneau', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Faible', pw_medium: 'Moyen', pw_strong: 'Fort', please_wait: 'Veuillez patienter...', success_heading: 'Compte cr\u00e9\u00e9 !', generate: 'G\u00e9n\u00e9rer', maintenance_heading: 'Mode maintenance', maintenance_text: 'Les nouvelles inscriptions sont actuellement suspendues pour maintenance. Veuillez r\u00e9essayer plus tard.', tos_prefix: 'J\'accepte les', tos_link: 'conditions d\'utilisation', tos_and: 'et la', privacy_link: 'politique de confidentialit\u00e9', did_you_mean: 'Vouliez-vous dire', setup_2fa: 'Nous recommandons d\'activer l\'authentification \u00e0 deux facteurs (2FA) dans le panneau.', copy_pw: 'Copier', need_help: 'Besoin d\'aide ?', contact_support: 'Contacter le support', forgot_password: 'Mot de passe oublié ?', pw_req_length: 'Au moins {n} caractères', pw_req_upper: 'Une majuscule (A-Z)', pw_req_lower: 'Une minuscule (a-z)', pw_req_number: 'Un chiffre (0-9)', email_mx_invalid: 'Le domaine de messagerie ne semble pas accepter de courrier.', pw_hibp_warning: '⚠️ Ce mot de passe est apparu dans {n} fuite(s) de données.', pw_hibp_ok: '✓ Mot de passe introuvable dans les fuites de données connues.', pw_hibp_checking: 'Vérification de la sécurité du mot de passe...', invite_code: 'Code d\'invitation', invite_code_ph: 'Entrez votre code d\'invitation', invite_required: 'Un code d\'invitation est requis pour s\'inscrire.', invite_invalid: 'Code d\'invitation invalide ou déjà utilisé.' },
      hu: { name: 'Magyar', subtitle: 'webes vez\u00e9rl\u0151pult', username: 'Felhaszn\u00e1l\u00f3n\u00e9v', username_ph: '4\u20138 karakter, a-z 0-9', email: 'E-mail c\u00edm', email_ph: 'felhasznalo@pelda.hu', domain: 'Domain', domain_ph: 'pelda.hu', password: 'Jelszó', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> karakter', confirm: 'Meger\u0151s\u00edt\u00e9s', confirm_ph: 'Ism\u00e9tl\u00e9s', register: 'Regisztr\u00e1ci\u00f3', already_registered: 'M\u00e1r regisztr\u00e1lt?', to_login: 'Bejelentkez\u00e9s', to_panel: 'A panelre', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Gyenge', pw_medium: 'K\u00f6zepes', pw_strong: 'Er\u0151s', please_wait: 'K\u00e9rj\u00fck v\u00e1rjon...', success_heading: 'Fi\u00f3k l\u00e9trehozva!', generate: 'Gener\u00e1l\u00e1s', maintenance_heading: 'Karbantart\u00e1si m\u00f3d', maintenance_text: '\u00daj regisztr\u00e1ci\u00f3k karbantart\u00e1s miatt jelenleg sz\u00fcnetelnek. K\u00e9rj\u00fck, pr\u00f3b\u00e1lja \u00fajra k\u00e9s\u0151bb.', tos_prefix: 'Elfogadom az', tos_link: '\u00c1ltal\u00e1nos Szerz\u0151d\u00e9si Felt\u00e9teleket', tos_and: '\u00e9s az', privacy_link: 'Adatvédelmi Nyilatkozatot', did_you_mean: 'Erre gondolt:', setup_2fa: 'Javasoljuk, hogy enged\u00e9lyezze a k\u00e9tl\u00e9pcs\u0151s azonos\u00edt\u00e1st (2FA) a panelen.', copy_pw: 'M\u00e1sol\u00e1s', need_help: 'Segítségre van szüksége?', contact_support: 'Kapcsolat a támogatással', forgot_password: 'Elfelejtett jelszó?', pw_req_length: 'Legalább {n} karakter', pw_req_upper: 'Egy nagybetű (A-Z)', pw_req_lower: 'Egy kisbetű (a-z)', pw_req_number: 'Egy szám (0-9)', email_mx_invalid: 'Úgy tűnik, hogy az e-mail domain nem fogad leveleket.', pw_hibp_warning: '⚠️ Ez a jelszó {n} adatszivárgásban szerepelt.', pw_hibp_ok: '✓ A jelszó nem található az ismert adatszivárgásokban.', pw_hibp_checking: 'Jelszó biztonságának ellenőrzése...', invite_code: 'Meghívó kód', invite_code_ph: 'Adja meg a meghívó kódját', invite_required: 'A regisztrációhoz meghívó kód szükséges.', invite_invalid: 'Érvénytelen vagy már felhasznált meghívó kód.' },
      it: { name: 'Italiano', subtitle: 'pannello di controllo web', username: 'Nome utente', username_ph: '4\u20138 caratt., a-z 0-9', email: 'Indirizzo e-mail', email_ph: 'utente@esempio.it', domain: 'Dominio', domain_ph: 'esempio.it', password: 'Password', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> caratt.', confirm: 'Conferma', confirm_ph: 'Ripeti', register: 'Registrati', already_registered: 'Gi\u00e0 registrato?', to_login: 'Accedi', to_panel: 'Al pannello', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Debole', pw_medium: 'Media', pw_strong: 'Forte', please_wait: 'Attendere prego...', success_heading: 'Account creato!', generate: 'Genera', maintenance_heading: 'Modalit\u00e0 di manutenzione', maintenance_text: 'Le nuove registrazioni sono momentaneamente sospese per manutenzione. Si prega di riprovare pi\u00f9 tardi.', tos_prefix: 'Accetto i', tos_link: 'Termini di Servizio', tos_and: 'e la', privacy_link: 'Informativa sulla Privacy', did_you_mean: 'Intendevi', setup_2fa: 'Ti consigliamo di abilitare l\'autenticazione a due fattori (2FA) nel pannello.', copy_pw: 'Copia', need_help: 'Hai bisogno di aiuto?', contact_support: 'Contatta il supporto', forgot_password: 'Password dimenticata?', pw_req_length: 'Almeno {n} caratteri', pw_req_upper: 'Una lettera maiuscola (A-Z)', pw_req_lower: 'Una lettera minuscola (a-z)', pw_req_number: 'Un numero (0-9)', email_mx_invalid: 'Il dominio email non sembra accettare posta.', pw_hibp_warning: '⚠️ Questa password è apparsa in {n} violazioni di dati.', pw_hibp_ok: '✓ Password non trovata in violazioni di dati note.', pw_hibp_checking: 'Controllo della sicurezza della password...', invite_code: 'Codice di invito', invite_code_ph: 'Inserisci il tuo codice di invito', invite_required: 'È richiesto un codice di invito per registrarsi.', invite_invalid: 'Codice di invito non valido o già utilizzato.' },
      ko: { name: '\ud55c\uad6d\uc5b4', subtitle: '\uc6f9 \uc81c\uc5b4\ud310', username: '\uc0ac\uc6a9\uc790 \uc774\ub984', username_ph: '4\u20138\uc790, a-z 0-9', email: '\uc774\uba54\uc77c \uc8fc\uc18c', email_ph: 'user@example.com', domain: '\ub3c4\uba54\uc778', domain_ph: 'example.com', password: '\ube44\ubc00\ubc88\ud638', password_ph: '\ucd5c\uc18c <?= PASSWD_MIN_LENGTH ?>\uc790', confirm: '\ube44\ubc00\ubc88\ud638 \ud655\uc778', confirm_ph: '\uc7ac\uc785\ub825', register: '\ud68c\uc6d0\uac00\uc785', already_registered: '\uc774\ubbf8 \uacc4\uc815\uc774 \uc788\uc73c\uc2e0\uac00\uc694?', to_login: '\ub85c\uadf8\uc778', to_panel: '\ud328\ub110\ub85c \uc774\ub3d9', pw_hint: 'A-Z, a-z, 0-9', pw_weak: '\uc57d\ud568', pw_medium: '\ubcf4\ud1b5', pw_strong: '\uac15\ud568', please_wait: '\uc7a0\uc2dc\ub9cc \uae30\ub2e4\ub824 \uc8fc\uc138\uc694...', success_heading: '\uacc4\uc815\uc774 \uc0dd\uc131\ub418\uc5c8\uc2b5\ub2c8\ub2e4!', generate: '\uc790\ub3d9 \uc0dd\uc131', maintenance_heading: '\uc810\uac80 \ubaa8\ub4dc', maintenance_text: '\uc720\uc9c0 \ubcf4\uc218\ub97c \uc704\ud574 \uc2e0\uaddc \ud68c\uc6d0\uac00\uc785\uc774 \uc77c\uc2dc \uc911\ub2e8\ub418\uc5c8\uc2b5\ub2c8\ub2e4. \ub098\uc911\uc5d0 \ub2e4\uc2dc \uc2dc\ub3c4\ud574 \uc8fc\uc138\uc694.', tos_prefix: '\ubcf8\uc778\uc740', tos_link: '\uc774\uc6a9\uc57d\uad00', tos_and: '\ubc0f', privacy_link: '\uac1c\uc778\uc815\ubcf4 \ucc98\ub9ac\ubc29\uce68\uc5d0 \ub3d9\uc758\ud569\ub2c8\ub2e4', did_you_mean: '\ub2e4\uc74c\uc744 \uc785\ub825\ud558\uc168\ub098\uc694:', setup_2fa: '\ud328\ub110\uc5d0\uc11c 2\ub2e8\uacc4 \uc778\uc99d(2FA)\uc744 \ud65c\uc131\ud654\ud558\ub294 \uac83\uc744 \uad8c\uc7a5\ud569\ub2c8\ub2e4.', copy_pw: '\ubcf5\uc0ac', need_help: '도움이 필요하신가요?', contact_support: '고객지원 문의', forgot_password: '비밀번호 찾기', pw_req_length: '최소 {n}자', pw_req_upper: '대문자 1개 이상 (A-Z)', pw_req_lower: '소문자 1개 이상 (a-z)', pw_req_number: '숫자 1개 이상 (0-9)', email_mx_invalid: '이메일 도메인이 메일을 수신하지 않는 것 같습니다.', pw_hibp_warning: '⚠️ 이 비밀번호는 {n}건의 데이터 유출에서 발견되었습니다.', pw_hibp_ok: '✓ 알려진 데이터 유출에서 비밀번호를 찾을 수 없습니다.', pw_hibp_checking: '비밀번호 보안 검사 중...', invite_code: '초대 코드', invite_code_ph: '초대 코드 입력', invite_required: '등록하려면 초대 코드가 필요합니다.', invite_invalid: '유효하지 않거나 이미 사용된 초대 코드입니다.' },
      lt: { name: 'Lietuvi\u0173', subtitle: 'valdymo skydas', username: 'Vartotojo vardas', username_ph: '4\u20138 simboliai, a-z 0-9', email: 'El. pa\u0161to adresas', email_ph: 'vartotojas@pavyzdys.lt', domain: 'Domenas', domain_ph: 'pavyzdys.lt', password: 'Slapta\u017eodis', password_ph: 'Ne ma\u017eiau <?= PASSWD_MIN_LENGTH ?> simp.', confirm: 'Patvirtinti', confirm_ph: 'Pakartoti', register: 'Registruotis', already_registered: 'Jau u\u017esiregistrav\u0119?', to_login: 'Prisijungti', to_panel: '\u012e valdymo skyd\u0105', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Silpnas', pw_medium: 'Vidutinis', pw_strong: 'Stiprus', please_wait: 'Pra\u0161ome palaukti...', success_heading: 'Paskyra sukurta!', generate: 'Generuoti', maintenance_heading: 'Prie\u017ei\u016bros re\u017eimas', maintenance_text: 'Naujos registracijos laikinai sustabdytos d\u0117l profilaktikos darb\u0173. Bandykite v\u0117liau.', tos_prefix: 'Sutinku su', tos_link: 'paslaugi\u0173 teikimo s\u0105lygomis', tos_and: 'ir', privacy_link: 'privatumo politika', did_you_mean: 'Ar tur\u0117jote omenyje', setup_2fa: 'Rekomenduojame skydelyje \u012fjungti dviej\u0173 veiksni\u0173 autentifikavim\u0105 (2FA).', copy_pw: 'Kopijuoti', need_help: 'Reikia pagalbos?', contact_support: 'Susisiekti su palaikymu', forgot_password: 'Pamiršote slaptažodį?', pw_req_length: 'Bent {n} simbolių', pw_req_upper: 'Viena didžioji raidė (A-Z)', pw_req_lower: 'Viena mažoji raidė (a-z)', pw_req_number: 'Vienas skaičius (0-9)', email_mx_invalid: 'Atrodo, kad el. pašto domenas nepriima pašto.', pw_hibp_warning: '⚠️ Šis slaptažodis pasirodė {n} duomenų nutekėjimuose.', pw_hibp_ok: '✓ Slaptažodis nerastas žinomuose duomenų nutekėjimuose.', pw_hibp_checking: 'Tikrinamas slaptažodžio saugumas...', invite_code: 'Kvietimo kodas', invite_code_ph: 'Įveskite kvietimo kodą', invite_required: 'Norint užsiregistruoti reikalingas kvietimo kodas.', invite_invalid: 'Neteisingas arba jau panaudotas kvietimo kodas.' },
      nl: { name: 'Nederlands', subtitle: 'webbeheerpaneel', username: 'Gebruikersnaam', username_ph: '4\u20138 tekens, a-z 0-9', email: 'E-mailadres', email_ph: 'gebruiker@voorbeeld.nl', domain: 'Domein', domain_ph: 'voorbeeld.nl', password: 'Wachtwoord', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> tekens', confirm: 'Bevestigen', confirm_ph: 'Herhalen', register: 'Registreren', already_registered: 'Al geregistreerd?', to_login: 'Inloggen', to_panel: 'Naar paneel', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Zwak', pw_medium: 'Gemiddeld', pw_strong: 'Sterk', please_wait: 'Even geduld...', success_heading: 'Account aangemaakt!', generate: 'Genereren', maintenance_heading: 'Onderhoudsmodus', maintenance_text: 'Nieuwe registraties zijn tijdelijk onderbroken voor onderhoud. Probeer het later opnieuw.', tos_prefix: 'Ik ga akkoord met de', tos_link: 'Algemene Voorwaarden', tos_and: 'en het', privacy_link: 'Privacybeleid', did_you_mean: 'Bedoelde u', setup_2fa: 'We raden aan om Tweestapsverificatie (2FA) in te schakelen in het paneel.', copy_pw: 'Kopi\u00ebren', need_help: 'Hulp nodig?', contact_support: 'Neem contact op met support', forgot_password: 'Wachtwoord vergeten?', pw_req_length: 'Minimaal {n} tekens', pw_req_upper: 'Eén hoofdletter (A-Z)', pw_req_lower: 'Eén kleine letter (a-z)', pw_req_number: 'Eén cijfer (0-9)', email_mx_invalid: 'Het e-maildomein lijkt geen e-mail te accepteren.', pw_hibp_warning: '⚠️ Dit wachtwoord verscheen in {n} datalekken.', pw_hibp_ok: '✓ Wachtwoord niet gevonden in bekende datalekken.', pw_hibp_checking: 'Wachtwoordbeveiliging controleren...', invite_code: 'Uitnodigingscode', invite_code_ph: 'Voer uw uitnodigingscode in', invite_required: 'Een uitnodigingscode is vereist om te registreren.', invite_invalid: 'Ongeldige of reeds gebruikte uitnodigingscode.' },
      pl: { name: 'Polski', subtitle: 'panel sterowania web', username: 'Nazwa u\u017cytkownika', username_ph: '4\u20138 znak\u00f3w, a-z 0-9', email: 'Adres e-mail', email_ph: 'uzytkownik@przyklad.pl', domain: 'Domena', domain_ph: 'przyklad.pl', password: 'Has\u0142o', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> znak\u00f3w', confirm: 'Potwierd\u017a', confirm_ph: 'Powt\u00f3rz', register: 'Zarejestruj si\u0119', already_registered: 'Masz ju\u017c konto?', to_login: 'Zaloguj si\u0119', to_panel: 'Do panelu', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'S\u0142abe', pw_medium: '\u015arednio', pw_strong: 'Mocne', please_wait: 'Prosz\u0119 czeka\u0107...', success_heading: 'Konto utworzone!', generate: 'Generuj', maintenance_heading: 'Tryb konserwacji', maintenance_text: 'Nowe rejestracje s\u0105 obecnie wstrzymane z powodu prac konserwacyjnych. Prosimy spr\u00f3bowa\u0107 p\u00f3\u017aniej.', tos_prefix: 'Akceptuj\u0119', tos_link: 'Regulamin', tos_and: 'oraz', privacy_link: 'Polityk\u0119 Prywatno\u015bci', did_you_mean: 'Czy chodzi\u0142o ci o', setup_2fa: 'Zalecamy w\u0142\u0105czenie uwierzytelniania dwusk\u0142adnikowego (2FA) w panelu.', copy_pw: 'Kopiuj', need_help: 'Potrzebujesz pomocy?', contact_support: 'Skontaktuj się ze wsparciem', forgot_password: 'Zapomniałeś hasła?', pw_req_length: 'Co najmniej {n} znaków', pw_req_upper: 'Jedna wielka litera (A-Z)', pw_req_lower: 'Jedna mała litera (a-z)', pw_req_number: 'Jedna cyfra (0-9)', email_mx_invalid: 'Wydaje się, że domena e-mail nie przyjmuje poczty.', pw_hibp_warning: '⚠️ To hasło pojawiło się w {n} wyciekach danych.', pw_hibp_ok: '✓ Hasło nie zostało znalezione w znanych wyciekach danych.', pw_hibp_checking: 'Sprawdzanie bezpieczeństwa hasła...', invite_code: 'Kod zaproszenia', invite_code_ph: 'Wprowadź swój kod zaproszenia', invite_required: 'Do rejestracji wymagany jest kod zaproszenia.', invite_invalid: 'Nieprawidłowy lub już użyty kod zaproszenia.' },
      es: { name: 'Espa\u00f1ol', subtitle: 'panel de control web', username: 'Nombre de usuario', username_ph: '4\u20138 car\u00e1ct., a-z 0-9', email: 'Correo electr\u00f3nico', email_ph: 'usuario@ejemplo.com', domain: 'Dominio', domain_ph: 'ejemplo.com', password: 'Contrase\u00f1a', password_ph: 'M\u00edn. <?= PASSWD_MIN_LENGTH ?> car\u00e1ct.', confirm: 'Confirmar', confirm_ph: 'Repetir', register: 'Registrarse', already_registered: '\u00bfYa tienes cuenta?', to_login: 'Iniciar sesi\u00f3n', to_panel: 'Al panel', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'D\u00e9bil', pw_medium: 'Media', pw_strong: 'Fuerte', please_wait: 'Por favor espere...', success_heading: '\u00a1Cuenta creada!', generate: 'Generar', maintenance_heading: 'Modo de mantenimiento', maintenance_text: 'Las nuevas inscripciones est\u00e1n pausadas temporalmente por mantenimiento. Por favor, vuelva a intentarlo m\u00e1s tarde.', tos_prefix: 'Acepto los', tos_link: 'T\u00e9rminos del Servicio', tos_and: 'y la', privacy_link: 'Pol\u00edtica de Privacidad', did_you_mean: '\u00bfQuisiste decir', setup_2fa: 'Recomendamos activar la autenticaci\u00f3n de dos factores (2FA) en el panel.', copy_pw: 'Copiar', need_help: '¿Necesitas ayuda?', contact_support: 'Contactar soporte', forgot_password: '¿Olvidaste tu contraseña?', pw_req_length: 'Al menos {n} caracteres', pw_req_upper: 'Una letra mayúscula (A-Z)', pw_req_lower: 'Una letra minúscula (a-z)', pw_req_number: 'Un número (0-9)', email_mx_invalid: 'El dominio de correo electrónico no parece aceptar correo.', pw_hibp_warning: '⚠️ Esta contraseña apareció en {n} filtración(es) de datos.', pw_hibp_ok: '✓ Contraseña no encontrada en filtraciones de datos conocidas.', pw_hibp_checking: 'Comprobando seguridad de la contraseña...', invite_code: 'Código de invitación', invite_code_ph: 'Ingresa tu código de invitación', invite_required: 'Se requiere un código de invitación para registrarse.', invite_invalid: 'Código de invitación no válido o ya utilizado.' },
      ru: { name: 'Русский', subtitle: 'панель управления web', username: 'Имя пользователя', username_ph: '4–8 симв., a-z 0-9', email: 'Электронная почта', email_ph: 'user@example.com', domain: 'Домен', domain_ph: 'example.com', password: 'Пароль', password_ph: 'Мин. <?= PASSWD_MIN_LENGTH ?> симв.', confirm: 'Подтверждение', confirm_ph: 'Повторите', register: 'Зарегистрироваться', already_registered: 'Уже зарегистрированы?', to_login: 'Войти', to_panel: 'В панель', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Слабый', pw_medium: 'Средний', pw_strong: 'Надежный', please_wait: 'Пожалуйста, подождите...', success_heading: 'Аккаунт создан!', generate: 'Сгенерировать', maintenance_heading: 'Режим обслуживания', maintenance_text: 'Новые регистрации временно приостановлены для проведения технических работ. Пожалуйста, зайдите позже.', tos_prefix: 'Я согласен с', tos_link: 'Условиями обслуживания', tos_and: 'и', privacy_link: 'Политикой конфиденциальности', did_you_mean: 'Возможно, вы имели в виду', setup_2fa: 'Мы рекомендуем включить двухфакторную аутентификацию (2FA) в панели.', copy_pw: 'Копировать', need_help: 'Нужна помощь?', contact_support: 'Связаться с поддержкой', forgot_password: 'Забыли пароль?', pw_req_length: 'Мин. {n} символов', pw_req_upper: 'Одна заглавная буква (A-Z)', pw_req_lower: 'Одна строчная буква (a-z)', pw_req_number: 'Одна цифра (0-9)', email_mx_invalid: 'Похоже, почтовый домен не принимает почту.', pw_hibp_warning: '⚠️ Этот пароль был найден в {n} утечках данных.', pw_hibp_ok: '✓ Пароль не найден в известных утечках данных.', pw_hibp_checking: 'Проверка безопасности пароля...', invite_code: 'Код приглашения', invite_code_ph: 'Введите код приглашения', invite_required: 'Для регистрации требуется код приглашения.', invite_invalid: 'Недействительный или уже использованный код приглашения.' },
      sl: { name: 'Slovenščina', subtitle: 'spletna nadzorna plošča', username: 'Uporabniško ime', username_ph: '4–8 znakov, a-z 0-9', email: 'E-poštni naslov', email_ph: 'uporabnik@primer.si', domain: 'Domena', domain_ph: 'primer.si', password: 'Geslo', password_ph: 'Najmanj <?= PASSWD_MIN_LENGTH ?> znakov', confirm: 'Potrdi', confirm_ph: 'Ponovi', register: 'Registracija', already_registered: 'Že registrirani?', to_login: 'Prijava', to_panel: 'V nadzorno ploščo', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Šibko', pw_medium: 'Srednje', pw_strong: 'Močno', please_wait: 'Prosimo, počakajte...', success_heading: 'Račun ustvarjen!', generate: 'Generiraj', maintenance_heading: 'Vzdrževalni način', maintenance_text: 'Nove registracije so trenutno zaustavljene zaradi vzdrževanja. Prosimo, poskusite znova pozneje.', tos_prefix: 'Strinjam se s', tos_link: 'pogoji storitve', tos_and: 'in', privacy_link: 'politiko zasebnosti', did_you_mean: 'Ali ste mislili', setup_2fa: 'Priporočamo, da v nadzorni plošči omogočite dvostopenjsko preverjanje (2FA).', copy_pw: 'Kopiraj', need_help: 'Potrebujete pomoč?', contact_support: 'Obrnite se na podporo', forgot_password: 'Ste pozabili geslo?', pw_req_length: 'Vsaj {n} znakov', pw_req_upper: 'Ena velika črka (A-Z)', pw_req_lower: 'Ena mala črka (a-z)', pw_req_number: 'Ena številka (0-9)', email_mx_invalid: 'Zdi se, da e-poštna domena ne sprejema pošte.', pw_hibp_warning: '⚠️ To geslo se je pojavilo v {n} kršitvah podatkov.', pw_hibp_ok: '✓ Geslo ni bilo najdeno v znanih kršitvah podatkov.', pw_hibp_checking: 'Preverjanje varnosti gesla...', invite_code: 'Koda povabila', invite_code_ph: 'Vnesite kodo povabila', invite_required: 'Za registracijo je potrebna koda povabila.', invite_invalid: 'Neveljavna ali že uporabljena koda povabila.' },
      sk: { name: 'Slovenčina', subtitle: 'webový ovládací panel', username: 'Používateľské meno', username_ph: '4–8 znakov, a-z 0-9', email: 'E-mailová adresa', email_ph: 'pouzivatel@priklad.sk', domain: 'Doména', domain_ph: 'priklad.sk', password: 'Heslo', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> znakov', confirm: 'Potvrdiť', confirm_ph: 'Opakovať', register: 'Registrovať', already_registered: 'Už máte účet?', to_login: 'Prihlásiť sa', to_panel: 'Do panela', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Slabé', pw_medium: 'Stredné', pw_strong: 'Silné', please_wait: 'Čakajte prosím...', success_heading: 'Účet bol vytvorený!', generate: 'Generovať', maintenance_heading: 'Režim údržby', maintenance_text: 'Nové registrácie sú z dôvodu údržby pozastavené. Skúste to prosím neskôr.', tos_prefix: 'Súhlasím s', tos_link: 'obchodnými podmienkami', tos_and: 'a', privacy_link: 'zásadami ochrany osobných údajov', did_you_mean: 'Mali ste na mysli', setup_2fa: 'Odporúčame v paneli zapnúť dvojfázové overenie (2FA).', copy_pw: 'Kopi\u00e9rova\u0165', need_help: 'Potrebujete pomoc?', contact_support: 'Kontaktovať podporu', forgot_password: 'Zabudnuté heslo?', pw_req_length: 'Aspoň {n} znakov', pw_req_upper: 'Jedno veľké písmeno (A-Z)', pw_req_lower: 'Jedno malé písmeno (a-z)', pw_req_number: 'Jedna číslica (0-9)', email_mx_invalid: 'Zdá sa, že doména e-mailu neprijíma poštu.', pw_hibp_warning: '⚠️ Toto heslo sa objavilo v {n} úniku dát.', pw_hibp_ok: '✓ Heslo nebolo nájdené v známych únikoch dát.', pw_hibp_checking: 'Kontrola bezpečnosti hesla...', invite_code: 'Pozývací kód', invite_code_ph: 'Zadajte svoj pozývací kód', invite_required: 'Na registráciu je potrebný pozývací kód.', invite_invalid: 'Neplatný alebo už použitý pozývací kód.' },
      sv: { name: 'Svenska', subtitle: 'webbkontrollpanel', username: 'Användarnamn', username_ph: '4–8 tecken, a-z 0-9', email: 'E-postadress', email_ph: 'anvandare@exempel.se', domain: 'Domän', domain_ph: 'exempel.se', password: 'Lösenord', password_ph: 'Minst <?= PASSWD_MIN_LENGTH ?> tecken', confirm: 'Bekräfta', confirm_ph: 'Upprepa', register: 'Registrera', already_registered: 'Redan registrerad?', to_login: 'Till inloggning', to_panel: 'Till panelen', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Svagt', pw_medium: 'Medel', pw_strong: 'Starkt', please_wait: 'Vänligen vänta...', success_heading: 'Konto skapat!', generate: 'Generera', maintenance_heading: 'Underhållsläge', maintenance_text: 'Nya registreringar är för närvarande pausade för underhåll. Vänligen återkom senare.', tos_prefix: 'Jag godkänner', tos_link: 'Användarvillkoren', tos_and: 'och', privacy_link: 'Integritetspolicyn', did_you_mean: 'Menade du', setup_2fa: 'Vi rekommenderar att du aktiverar tvåfaktorsautentisering (2FA) i panelen.', copy_pw: 'Kopiera', need_help: 'Behöver du hjälp?', contact_support: 'Kontakta support', forgot_password: 'Glömt lösenord?', pw_req_length: 'Minst {n} tecken', pw_req_upper: 'En stor bokstav (A-Z)', pw_req_lower: 'En liten bokstav (a-z)', pw_req_number: 'En siffra (0-9)', email_mx_invalid: 'E-postdomänen verkar inte acceptera e-post.', pw_hibp_warning: '⚠️ Detta lösenord dök upp i {n} dataläckor.', pw_hibp_ok: '✓ Lösenord hittades inte i kända dataläckor.', pw_hibp_checking: 'Kontrollerar lösenordssäkerhet...', invite_code: 'Inbjudningskod', invite_code_ph: 'Ange din inbjudningskod', invite_required: 'En inbjudningskod krävs för att registrera.', invite_invalid: 'Ogiltig eller redan använd inbjudningskod.' },
      tr: { name: 'Türkçe', subtitle: 'web kontrol paneli', username: 'Kullanıcı adı', username_ph: '4–8 karak., a-z 0-9', email: 'E-posta adresi', email_ph: 'kullanici@ornek.com', domain: 'Alan adı', domain_ph: 'ornek.com', password: 'Şifre', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> karak.', confirm: 'Doğrula', confirm_ph: 'Tekrar', register: 'Kayıt Ol', already_registered: 'Zaten kayıtlı mısınız?', to_login: 'Giriş Yap', to_panel: 'Panele Git', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Zayıf', pw_medium: 'Orta', pw_strong: 'Güçlü', please_wait: 'Lütfen bekleyin...', success_heading: 'Hesap Oluşturuldu!', generate: 'Oluştur', maintenance_heading: 'Bakım Modu', maintenance_text: 'Yeni kayıtlar bakım nedeniyle geçici olarak durdurulmuştur. Lütfen daha sonra tekrar deneyin.', tos_prefix: '', tos_link: 'Kullanım Koşullarını', tos_and: 've', privacy_link: 'Gizlilik Politikasını kabul ediyorum', did_you_mean: 'Bunu mu demek istediniz:', setup_2fa: 'Panelden İki Faktörlü Kimlik Doğrulamayı (2FA) etkinleştirmenizi öneririz.', copy_pw: 'Kopyala', need_help: 'Yardıma mı ihtiyacınız var?', contact_support: 'Destekle iletişime geç', forgot_password: 'Şifremi Unuttum?', pw_req_length: 'En az {n} karakter', pw_req_upper: 'Bir büyük harf (A-Z)', pw_req_lower: 'Bir küçük harf (a-z)', pw_req_number: 'Bir rakam (0-9)', email_mx_invalid: 'E-posta etki alanı posta kabul etmiyor gibi görünüyor.', pw_hibp_warning: '⚠️ Bu şifre {n} veri ihlalinde göründü.', pw_hibp_ok: '✓ Şifre bilinen veri ihlallerinde bulunamadı.', pw_hibp_checking: 'Şifre güvenliği kontrol ediliyor...', invite_code: 'Davet Kodu', invite_code_ph: 'Davet kodunuzu girin', invite_required: 'Kayıt olmak için davet kodu gereklidir.', invite_invalid: 'Geçersiz veya zaten kullanılmış davet kodu.' },
      uk: { name: 'Українська', subtitle: 'панель керування web', username: 'Ім\'я користувача', username_ph: '4–8 симв., a-z 0-9', email: 'Електронна пошта', email_ph: 'user@example.com', domain: 'Домен', domain_ph: 'example.com', password: 'Пароль', password_ph: 'Мін. <?= PASSWD_MIN_LENGTH ?> симв.', confirm: 'Підтвердження', confirm_ph: 'Повторіть', register: 'Зареєструватися', already_registered: 'Вже маєте акаунт?', to_login: 'Увійти', to_panel: 'До панелі', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Слабкий', pw_medium: 'Середній', pw_strong: 'Надійний', please_wait: 'Будь ласка, зачекайте...', success_heading: 'Акаунт створено!', generate: 'Згенерувати', maintenance_heading: 'Режим обслуговування', maintenance_text: 'Нові реєстрації тимчасово призупинено через технічні роботи. Будь ласка, спробуйте пізніше.', tos_prefix: 'Я погоджуюся з', tos_link: 'Умовами обслуговування', tos_and: 'та', privacy_link: 'Політикою конфіденційності', did_you_mean: 'Можливо, ви мали на увазі', setup_2fa: 'Ми рекомендуємо ввімкнути двофакторну автентифікацію (2FA) у панелі.', copy_pw: 'Копіювати', need_help: 'Потрібна допомога?', contact_support: 'Зв\'язатися з підтримкою', forgot_password: 'Забули пароль?', pw_req_length: 'Мін. {n} символів', pw_req_upper: 'Одна велика літера (A-Z)', pw_req_lower: 'Одна мала літера (a-z)', pw_req_number: 'Одна цифра (0-9)', email_mx_invalid: 'Схоже, поштовий домен не приймає пошту.', pw_hibp_warning: '⚠️ Цей пароль знайдено у {n} витоках даних.', pw_hibp_ok: '✓ Пароль не знайдено у відомих витоках даних.', pw_hibp_checking: 'Перевірка безпеки пароля...', invite_code: 'Код запрошення', invite_code_ph: 'Введіть код запрошення', invite_required: 'Для реєстрації потрібен код запрошення.', invite_invalid: 'Недійсний або вже використаний код запрошення.' },
      uz: { name: 'Oʻzbekcha', subtitle: 'veb boshqaruv paneli', username: 'Foydalanuvchi nomi', username_ph: '4–8 belgi, a-z 0-9', email: 'E-pochta manzili', email_ph: 'foydalanuvchi@namuna.uz', domain: 'Domen', domain_ph: 'namuna.uz', password: 'Parol', password_ph: 'Kamida <?= PASSWD_MIN_LENGTH ?> belgi', confirm: 'Tasdiqlash', confirm_ph: 'Takrorlang', register: 'Roʻyxatdan oʻtish', already_registered: 'Roʻyxatdan oʻtganmisiz?', to_login: 'Kirish', to_panel: 'Panelga oʻtish', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Zarif', pw_medium: 'Oʻrtacha', pw_strong: 'Kuchli', please_wait: 'Kuting...', success_heading: 'Hisob yaratildi!', generate: 'Yaratish', maintenance_heading: 'Profilaktika rejimi', maintenance_text: 'Yangi roʻyxatdan oʻtishlar profilaktika ishlari sababli vaqtincha toʻxtatilgan. Keyinroq qayta urinib koʻring.', tos_prefix: 'Men', tos_link: 'Xizmat koʻrsatish shartlari', tos_and: 'va', privacy_link: 'Maxfiylik siyosatiga roziman', did_you_mean: 'Buni nazarda tutdingizmi:', setup_2fa: 'Panelda Ikki faktorli autentifikatsiyani (2FA) yoqishingizni tavsiya qilamiz.', copy_pw: 'Nusxalash', need_help: 'Yordam kerakmi?', contact_support: 'Qo\'llab-quvvatlash bilan bog\'lanish', forgot_password: 'Parolni unutdingizmi?', pw_req_length: 'Kamida {n} ta belgi', pw_req_upper: 'Bitta bosh harf (A-Z)', pw_req_lower: 'Bitta kichik harf (a-z)', pw_req_number: 'Bitta raqam (0-9)', email_mx_invalid: 'Elektron pochta domeni xatlarni qabul qilmayotganga o‘xshaydi.', pw_hibp_warning: '⚠️ Ushbu parol {n} ta ma\'lumotlar sizib chiqishida paydo bo\'lgan.', pw_hibp_ok: '✓ Parol ma\'lum bo\'lgan ma\'lumotlar sizib chiqishida topilmadi.', pw_hibp_checking: 'Parol xavfsizligi tekshirilmoqda...', invite_code: 'Taklif kodi', invite_code_ph: 'Taklif kodini kiriting', invite_required: 'Ro\'yxatdan o\'tish uchun taklif kodi kerak.', invite_invalid: 'Yaroqsiz yoki oldin ishlatilgan taklif kodi.' },
      th: { name: 'ไทย', subtitle: 'แผงควบคุมเว็บ', username: 'ชื่อผู้ใช้', username_ph: '4–8 ตัวอักษร, a-z 0-9', email: 'อีเมล', email_ph: 'user@example.com', domain: 'โดเมน', domain_ph: 'example.com', password: 'รหัสผ่าน', password_ph: 'อย่างน้อย <?= PASSWD_MIN_LENGTH ?> ตัวอักษร', confirm: 'ยืนยันรหัสผ่าน', confirm_ph: 'ป้อนอีกครั้ง', register: 'ลงทะเบียน', already_registered: 'มีบัญชีอยู่แล้ว?', to_login: 'เข้าสู่ระบบ', to_panel: 'ไปที่พาเนล', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'อ่อน', pw_medium: 'ปานกลาง', pw_strong: 'แข็งแกร่ง', please_wait: 'โปรดรอสักครู่...', success_heading: 'สร้างบัญชีแล้ว!', generate: 'สร้างรหัส', maintenance_heading: 'โหมดปรับปรุงระบบ', maintenance_text: 'เปิดปิดการลงทะเบียนใหม่ชั่วคราวเพื่อปรับปรุงระบบ โปรดลองอีกครั้งในภายหลัง', tos_prefix: 'ฉันยอมรับ', tos_link: 'ข้อตกลงการใช้บริการ', tos_and: 'และ', privacy_link: 'นโยบายความเป็นส่วนตัว', did_you_mean: 'คุณหมายถึง', setup_2fa: 'เราขอแนะนำให้เปิดใช้งานการยืนยันแบบสองขั้นตอน (2FA) ในแผงควบคุม', need_help: 'ต้องการความช่วยเหลือ?', contact_support: 'ติดต่อฝ่ายสนับสนุน', forgot_password: 'ลืมรหัสผ่าน?', pw_req_length: 'อย่างน้อย {n} ตัวอักษร', pw_req_upper: 'ตัวพิมพ์ใหญ่ 1 ตัว (A-Z)', pw_req_lower: 'ตัวพิมพ์เล็ก 1 ตัว (a-z)', pw_req_number: 'ตัวเลข 1 ตัว (0-9)', email_mx_invalid: 'โดเมนอีเมลดูเหมือนจะไม่รับเมล', pw_hibp_warning: '⚠️ รหัสผ่านนี้ปรากฏในข้อมูลรั่วไหล {n} ครั้ง', pw_hibp_ok: '✓ ไม่พบรหัสผ่านในข้อมูลรั่วไหลที่ทราบ', pw_hibp_checking: 'กำลังตรวจสอบความปลอดภัยของรหัสผ่าน...', invite_code: 'รหัสคำเชิญ', invite_code_ph: 'ใส่รหัสคำเชิญของคุณ', invite_required: 'ต้องใช้รหัสคำเชิญในการลงทะเบียน', invite_invalid: 'รหัสคำเชิญไม่ถูกต้องหรือถูกใช้ไปแล้ว' },
      zh: { name: '简体中文', subtitle: 'Web 控制面板', username: '用户名', username_ph: '4–8个字符, a-z 0-9', email: '电子邮件', email_ph: 'user@example.com', domain: '域名', domain_ph: 'example.com', password: '密码', password_ph: '至少 <?= PASSWD_MIN_LENGTH ?> 个字符', confirm: '确认密码', confirm_ph: '重复密码', register: '注册', already_registered: '已有账号？', to_login: '去登录', to_panel: '前往控制面板', pw_hint: 'A-Z, a-z, 0-9', pw_weak: '弱', pw_medium: '中', pw_strong: '强', please_wait: '请稍候...', success_heading: '账号已创建！', generate: '生成密码', maintenance_heading: '维护模式', maintenance_text: '由于系统维护，新用户注册已暂停。请稍后再试。', tos_prefix: '我同意', tos_link: '服务条款', tos_and: '和', privacy_link: '隐私政策', did_you_mean: '您是说', setup_2fa: '我们建议您在面板中启用双因素身份验证 (2FA)。', copy_pw: '\u590d\u5236', need_help: '需要帮助吗？', contact_support: '联系支持', forgot_password: '忘记密码？', pw_req_length: '至少 {n} 个字符', pw_req_upper: '一个大写字母 (A-Z)', pw_req_lower: '一个小写字母 (a-z)', pw_req_number: '一个数字 (0-9)', email_mx_invalid: '该电子邮件域名似乎不接收邮件。', pw_hibp_warning: '⚠️ 此密码已在 {n} 次数据泄露中出现。', pw_hibp_ok: '✓ 在已知数据泄露中未找到此密码。', pw_hibp_checking: '正在检查密码安全性...', invite_code: '邀请码', invite_code_ph: '请输入您的邀请码', invite_required: '注册需要邀请码。', invite_invalid: '邀请码无效或已使用。' },
      pt: {
        name: 'Português',
        subtitle: 'painel de controlo web',
        username: 'Nome de utilizador',
        username_ph: '4–8 caracteres, a-z 0-9',
        email: 'Endereço de e-mail',
        email_ph: 'utilizador@exemplo.pt',
        domain: 'Domínio',
        domain_ph: 'exemplo.pt',
        password: 'Palavra-passe',
        password_ph: 'Mín. <?= PASSWD_MIN_LENGTH ?> caracteres',
        confirm: 'Confirmar',
        confirm_ph: 'Repetir',
        register: 'Registar',
        already_registered: 'Já registado?',
        to_login: 'Entrar',
        to_panel: 'Ir para o painel',
        pw_hint: 'A-Z, a-z, 0-9',
        pw_weak: 'Fraca',
        pw_medium: 'Média',
        pw_strong: 'Forte',
        please_wait: 'Por favor, aguarde...',
        success_heading: 'Conta criada!',
        generate: 'Gerar',
        maintenance_heading: 'Modo de manutenção',
        maintenance_text: 'Novos registos estão temporariamente suspensos para manutenção. Por favor, tente mais tarde.',
        tos_prefix: 'Aceito os',
        tos_link: 'Termos de Serviço',
        tos_and: 'e a',
        privacy_link: 'Política de Privacidade',
        did_you_mean: 'Queria dizer',
        setup_2fa: 'Recomendamos a ativação da autenticação de dois fatores (2FA) no painel.',
        copy_pw: 'Copiar',
        need_help: 'Precisa de ajuda?',
        contact_support: 'Contactar o Suporte',
        forgot_password: 'Esqueceu-se da palavra-passe?',
        pw_req_length: 'Pelo menos {n} caracteres',
        pw_req_upper: 'Uma letra maiúscula (A-Z)',
        pw_req_lower: 'Uma letra minúscula (a-z)',
        pw_req_number: 'Um número (0-9)',
        email_mx_invalid: 'O domínio do e-mail parece não aceitar mensagens.',
        pw_hibp_warning: '⚠️ Esta palavra-passe foi encontrada em {n} fugas de dados.',
        pw_hibp_ok: '✓ Palavra-passe não encontrada em fugas de dados conhecidas.',
        pw_hibp_checking: 'A verificar a segurança da palavra-passe...',
        invite_code: 'Código de convite',
        invite_code_ph: 'Introduza o seu código de convite',
        invite_required: 'É necessário um código de convite para se registar.',
        invite_invalid: 'Código de convite inválido ou já utilizado.'
      },
      pt_br: {
        name: 'Português (Brasil)',
        subtitle: 'painel de controle web',
        username: 'Nome de usuário',
        username_ph: '4–8 caracteres, a-z 0-9',
        email: 'Endereço de e-mail',
        email_ph: 'usuario@exemplo.com.br',
        domain: 'Domínio',
        domain_ph: 'exemplo.com.br',
        password: 'Senha',
        password_ph: 'Mín. <?= PASSWD_MIN_LENGTH ?> caracteres',
        confirm: 'Confirmar',
        confirm_ph: 'Repetir',
        register: 'Cadastrar',
        already_registered: 'Já cadastrado?',
        to_login: 'Entrar',
        to_panel: 'Ir para o painel',
        pw_hint: 'A-Z, a-z, 0-9',
        pw_weak: 'Fraca',
        pw_medium: 'Média',
        pw_strong: 'Forte',
        please_wait: 'Por favor, aguarde...',
        success_heading: 'Conta criada!',
        generate: 'Gerar',
        maintenance_heading: 'Modo de manutenção',
        maintenance_text: 'Novos cadastros estão temporariamente suspensos para manutenção. Por favor, tente mais tarde.',
        tos_prefix: 'Aceito os',
        tos_link: 'Termos de Serviço',
        tos_and: 'e a',
        privacy_link: 'Política de Privacidade',
        did_you_mean: 'Você quis dizer',
        setup_2fa: 'Recomendamos a ativação da autenticação de dois fatores (2FA) no painel.',
        copy_pw: 'Copiar',
        need_help: 'Precisa de ajuda?',
        contact_support: 'Contatar o Suporte',
        forgot_password: 'Esqueceu a senha?',
        pw_req_length: 'Pelo menos {n} caracteres',
        pw_req_upper: 'Uma letra maiúscula (A-Z)',
        pw_req_lower: 'Uma letra minúscula (a-z)',
        pw_req_number: 'Um número (0-9)',
        email_mx_invalid: 'O domínio do e-mail parece não aceitar mensagens.',
        pw_hibp_warning: '⚠️ Esta senha foi encontrada em {n} vazamentos de dados.',
        pw_hibp_ok: '✓ Senha não encontrada em vazamentos de dados conhecidos.',
        pw_hibp_checking: 'Verificando a segurança da senha...',
        invite_code: 'Código de convite',
        invite_code_ph: 'Digite seu código de convite',
        invite_required: 'É necessário um código de convite para se cadastrar.',
        invite_invalid: 'Código de convite inválido ou já utilizado.'
      },
      ja: {
        name: '日本語',
        subtitle: 'Web コントロールパネル',
        username: 'ユーザー名',
        username_ph: '4–8文字、a-z 0-9',
        email: 'メールアドレス',
        email_ph: 'user@example.jp',
        domain: 'ドメイン',
        domain_ph: 'example.jp',
        password: 'パスワード',
        password_ph: '最小 <?= PASSWD_MIN_LENGTH ?> 文字',
        confirm: 'パスワード確認',
        confirm_ph: 'もう一度入力',
        register: '登録する',
        already_registered: '既に登録されていますか？',
        to_login: 'ログイン',
        to_panel: 'パネルへ',
        pw_hint: 'A-Z, a-z, 0-9',
        pw_weak: '弱い',
        pw_medium: '普通',
        pw_strong: '強い',
        please_wait: '少々お待ちください...',
        success_heading: 'アカウントが作成されました！',
        generate: '自動生成',
        maintenance_heading: 'メンテナンスモード',
        maintenance_text: '現在、メンテナンスのため新規登録を一時的に停止しています。後ほどもう一度お試しください。',
        tos_prefix: '私は',
        tos_link: '利用規約',
        tos_and: 'および',
        privacy_link: 'プライバシーポリシーに同意します',
        did_you_mean: 'もしかして',
        setup_2fa: 'パネル内で2要素認証 (2FA) を有効にすることをお勧めします。',
        copy_pw: 'コピー',
        need_help: 'ヘルプが必要ですか？',
        contact_support: 'サポートに連絡',
        forgot_password: 'パスワードをお忘れですか？',
        pw_req_length: '最小 {n} 文字以上',
        pw_req_upper: '大文字1文字以上 (A-Z)',
        pw_req_lower: '小文字1文字以上 (a-z)',
        pw_req_number: '数字1文字以上 (0-9)',
        email_mx_invalid: 'メールのドメインがメールを受信できない状態のようです。',
        pw_hibp_warning: '⚠️ このパスワードは過去に {n} 件のデータ漏洩で確認されています。',
        pw_hibp_ok: '✓ このパスワードは既知のデータ漏洩では見つかりませんでした。',
        pw_hibp_checking: 'パスワードの安全性を確認中...',
        invite_code: '招待コード',
        invite_code_ph: '招待コードを入力してください',
        invite_required: '登録には招待コードが必要です。',
        invite_invalid: '招待コードが無効か、または既に使用されています。'
      }
    };

    const langDropdown = document.getElementById('langDropdown');
    const langBtn = document.getElementById('langBtn');

    // ── Password Generator ─────────────────────────────────────────────────────
    const generatePwBtn = document.getElementById('generatePwBtn');
    if (generatePwBtn) generatePwBtn.addEventListener('click', generatePassword);

    function generatePassword() {
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
      let pwd = "";
      pwd += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[Math.floor(Math.random() * 26)];
      pwd += "abcdefghijklmnopqrstuvwxyz"[Math.floor(Math.random() * 26)];
      pwd += "0123456789"[Math.floor(Math.random() * 10)];
      for (let i = 0; i < 9; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
      pwd = pwd.split('').sort(() => 0.5 - Math.random()).join('');

      const p1 = document.getElementById('passwd');
      const p2 = document.getElementById('passwd2');
      p1.value = pwd;
      p2.value = pwd;

      // Briefly show password so user can see what was generated
      p1.type = 'text'; p2.type = 'text';
      // Update eye button icons
      document.querySelectorAll('.eye-btn').forEach(btn => {
        btn.querySelector('.show-icon').style.display = 'none';
        btn.querySelector('.hide-icon').style.display = 'block';
      });
      p1.dispatchEvent(new Event('input'));

      // Show copy button
      const copyBtn = document.getElementById('copyPwBtn');
      if (copyBtn) copyBtn.style.display = 'flex';

      setTimeout(() => {
        p1.type = 'password'; p2.type = 'password';
        document.querySelectorAll('.eye-btn').forEach(btn => {
          btn.querySelector('.show-icon').style.display = 'block';
          btn.querySelector('.hide-icon').style.display = 'none';
        });
      }, 4000);
    }

    // ── Eye Toggle (Password Visibility) ──────────────────────────────────────
    document.querySelectorAll('.eye-btn').forEach(btn => {
      btn.addEventListener('click', function () {
        const targetId = this.dataset.target;
        const input = document.getElementById(targetId);
        if (!input) return;
        const isHidden = input.type === 'password';
        input.type = isHidden ? 'text' : 'password';
        this.querySelector('.show-icon').style.display = isHidden ? 'none' : 'block';
        this.querySelector('.hide-icon').style.display = isHidden ? 'block' : 'none';
      });
    });

    // ── Copy Password Button ───────────────────────────────────────────────────
    const copyPwBtn = document.getElementById('copyPwBtn');
    if (copyPwBtn) {
      copyPwBtn.addEventListener('click', function () {
        const pw = document.getElementById('passwd')?.value;
        if (!pw) return;
        navigator.clipboard.writeText(pw).then(() => {
          this.classList.add('copied');
          const label = this.querySelector('#copyPwLabel');
          const origText = label.textContent;
          label.textContent = '✓';
          setTimeout(() => {
            this.classList.remove('copied');
            label.textContent = origText;
          }, 2000);
        });
      });
    }

    // Show copy button when user types password manually
    if (pwInput) {
      pwInput.addEventListener('input', function () {
        const copyBtn = document.getElementById('copyPwBtn');
        if (copyBtn) copyBtn.style.display = this.value ? 'flex' : 'none';
      });
    }

    let currentLang = 'en';
    function setLanguage(langCode) {
      currentLang = langCode;
      const dict = I18N[langCode] || I18N['en'];
      localStorage.setItem('da_lang', langCode);
      document.getElementById('currentLangLabel').textContent = dict.name;

      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (dict[key]) el.textContent = dict[key];
      });

      document.querySelectorAll('[data-i18n-ph]').forEach(el => {
        const key = el.dataset.i18nPh;
        if (dict[key]) el.placeholder = dict[key];
      });

      document.querySelectorAll('[data-i18n-min]').forEach(el => {
        const key = el.dataset.i18nMin;
        const checklist = document.getElementById('pwChecklist');
        const minLen = checklist ? checklist.dataset.min : 8;
        if (dict[key]) el.textContent = dict[key].replace('{n}', minLen);
      });

      document.querySelectorAll('.lang-item').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.lang === langCode);
      });
    }

    if (langDropdown && langBtn) {
      Object.keys(I18N).forEach(code => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'lang-item';
        item.dataset.lang = code;
        item.textContent = I18N[code].name;
        item.addEventListener('click', () => {
          setLanguage(code);
          langDropdown.classList.remove('show');
        });
        langDropdown.appendChild(item);
      });

      langBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        langDropdown.classList.toggle('show');
      });

      document.addEventListener('click', (e) => {
        const langWrap = document.getElementById('langWrap');
        if (langWrap && !langWrap.contains(e.target)) {
          langDropdown.classList.remove('show');
        }
      });

      // Init language from localStorage or browser settings
      const savedLang = localStorage.getItem('da_lang') || navigator.language.slice(0, 2);
      setLanguage(I18N[savedLang] ? savedLang : 'en');
    }

    // ── Client-Side Validation & Submit Spinner ───────────────────────────────
    const regForm = document.getElementById('regForm');
    if (regForm) {
      regForm.addEventListener('submit', function (e) {
        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const domain = document.getElementById('domain').value.trim();
        const pw = document.getElementById('passwd').value;
        const pw2 = document.getElementById('passwd2').value;

        if (!/^[a-z0-9]{4,8}$/i.test(username)) {
          e.preventDefault();
          alert('Username: 4–8 characters, only a-z and 0-9 allowed.');
          return;
        }
        if (!email.includes('@')) {
          e.preventDefault();
          alert('Please enter a valid email address.');
          return;
        }
        if (!domain.match(/^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$/i)) {
          e.preventDefault();
          alert('Please enter a valid domain (e.g. example.com).');
          return;
        }
        if (pw.length < <?= PASSWD_MIN_LENGTH ?>) {
          e.preventDefault();
          alert('Password must be at least <?= PASSWD_MIN_LENGTH ?> characters long.');
          return;
        }
        <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
          if (!/[A-Z]/.test(pw) || !/[a-z]/.test(pw) || !/[0-9]/.test(pw)) {
            e.preventDefault();
            alert('Password must contain at least one uppercase letter, one lowercase letter, and one number.');
            return;
          }
        <?php endif; ?>
        if (pw !== pw2) {
          e.preventDefault();
          alert('Passwords do not match.');
          return;
        }

        const btn = document.getElementById('submitBtn');
        const spinner = document.getElementById('spinner');
        const label = document.getElementById('submitLabel');
        if (btn) btn.disabled = true;
        if (spinner) spinner.style.display = 'block';
        const curLang = localStorage.getItem('da_lang') || 'en';
        if (label) label.textContent = (I18N[curLang] || I18N['en']).please_wait || 'Please wait...';
      });
    }

    // ── Hide Preloader after page load ────────────────────────────────────────
    window.addEventListener('load', () => {
      const preloader = document.getElementById('preloader');
      if (preloader) {
        preloader.classList.add('hidden');
        // Remove from DOM after transition to free resources
        preloader.addEventListener('transitionend', () => preloader.remove(), { once: true });
      }
    });

    // ── Email Typo Detection ──────────────────────────────────────────────────
    const emailInput = document.getElementById('email');
    const emailSuggestion = document.getElementById('emailSuggestion');
    const emailSuggestionLink = document.getElementById('emailSuggestionLink');

    if (emailInput && emailSuggestion && emailSuggestionLink) {
      const commonDomains = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com',
        'gmx.de', 'gmx.net', 'gmx.at', 'gmx.ch', 'web.de', 't-online.de', 'freenet.de', 'posteo.de', 'mailbox.org',
        'yandex.ru', 'mail.ru', 'inbox.ru', 'bk.ru', 'list.ru', 'rambler.ru',
        'proton.me', 'protonmail.com', 'tuta.com', 'tutamail.com',
        'live.com', 'msn.com', 'zoho.com'
      ];

      function calculateDistance(a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;
        const matrix = [];
        for (let i = 0; i <= b.length; i++) matrix[i] = [i];
        for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
        for (let i = 1; i <= b.length; i++) {
          for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
              matrix[i][j] = matrix[i - 1][j - 1];
            } else {
              matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));
            }
          }
        }
        return matrix[b.length][a.length];
      }

      emailInput.addEventListener('blur', function () {
        const val = this.value.trim().toLowerCase();
        const parts = val.split('@');
        if (parts.length === 2 && parts[1].length > 0) {
          const user = parts[0];
          const domain = parts[1];
          let bestMatch = null;
          let minDistance = 3;

          if (commonDomains.includes(domain)) {
            emailSuggestion.style.display = 'none';
            return;
          }

          for (const cd of commonDomains) {
            const d = calculateDistance(domain, cd);
            if (d < minDistance) {
              minDistance = d;
              bestMatch = cd;
            }
          }

          if (bestMatch && bestMatch !== domain) {
            const suggestedEmail = user + '@' + bestMatch;
            emailSuggestionLink.textContent = suggestedEmail;
            emailSuggestion.style.display = 'block';

            emailSuggestionLink.onclick = function (e) {
              e.preventDefault();
              emailInput.value = suggestedEmail;
              emailSuggestion.style.display = 'none';
              emailInput.focus();
            };
          } else {
            emailSuggestion.style.display = 'none';
          }
        } else {
          emailSuggestion.style.display = 'none';
        }
      });
    }

    // Close help menu on outside click
    window.addEventListener('click', function (e) {
      const hm = document.getElementById('helpMenu');
      if (hm && hm.classList.contains('show') && !e.target.closest('#helpFabWrap')) {
        hm.classList.remove('show');
      }
    });

    // Help FAB toggle
    const helpFabBtn = document.getElementById('helpFabBtn');
    if (helpFabBtn) {
      helpFabBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        document.getElementById('helpMenu').classList.toggle('show');
      });
    }

    // ── Password Checklist ──────────────────────────────────────────────────
    (function() {
      const checklist = document.getElementById('pwChecklist');
      if (!checklist) return;

      const minLen     = parseInt(checklist.dataset.min, 10) || 8;
      const complexity = checklist.dataset.complexity === '1';
      const pwInput    = document.getElementById('passwd');
      if (!pwInput) return;

      const chkLength = document.getElementById('chk-length');
      const chkUpper  = document.getElementById('chk-upper');
      const chkLower  = document.getElementById('chk-lower');
      const chkNumber = document.getElementById('chk-number');

      function setCheck(el, ok) {
        if (!el) return;
        el.classList.toggle('ok', ok);
        el.querySelector('.check-icon').textContent = ok ? '✓' : '';
      }

      function updateChecklist() {
        const val = pwInput.value;
        setCheck(chkLength, val.length >= minLen);
        if (complexity) {
          setCheck(chkUpper,  /[A-Z]/.test(val));
          setCheck(chkLower,  /[a-z]/.test(val));
          setCheck(chkNumber, /[0-9]/.test(val));
        }
        // Update i18n placeholder for min-length text
        if (chkLength) {
          const span = chkLength.querySelector('[data-i18n-min]');
          if (span) {
            const key = span.dataset.i18nMin;
            const lang = I18N[currentLang] || I18N['en'] || {};
            const tpl  = lang[key] || `At least ${minLen} characters`;
            span.textContent = tpl.replace('{n}', minLen);
          }
        }
      }

      pwInput.addEventListener('input', updateChecklist);
      updateChecklist();
    })();

    // ── HaveIBeenPwned Check ────────────────────────────────────────────────
    <?php if (defined('ENABLE_HIBP_CHECK') && ENABLE_HIBP_CHECK): ?>
    (function() {
      const pwInput    = document.getElementById('passwd');
      const hibpStatus = document.getElementById('hibpStatus');
      const form       = document.getElementById('regForm');
      if (!pwInput || !hibpStatus) return;

      const blockOnBreach = <?= defined('HIBP_BLOCK_ON_BREACH') && HIBP_BLOCK_ON_BREACH ? 'true' : 'false' ?>;
      let hibpTimer = null;
      let lastBreach = false;

      // Compute SHA-1 using Web Crypto API (no external lib needed)
      async function sha1(str) {
        const buf  = new TextEncoder().encode(str);
        const hash = await crypto.subtle.digest('SHA-1', buf);
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      }

      async function checkHibp(password) {
        if (password.length < 4) {
          hibpStatus.className = 'hibp-status';
          lastBreach = false;
          return;
        }

        const lang = I18N[currentLang] || I18N['en'] || {};
        hibpStatus.className = 'hibp-status checking';
        hibpStatus.textContent = lang.pw_hibp_checking || 'Checking password security...';

        try {
          const hash   = await sha1(password);
          const prefix = hash.substring(0, 5);
          const suffix = hash.substring(5);

          const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            headers: { 'Add-Padding': 'true' }
          });
          if (!resp.ok) throw new Error('HIBP API error');

          const text = await resp.text();
          let count  = 0;
          for (const line of text.split('\n')) {
            const [s, c] = line.trim().split(':');
            if (s && s.toUpperCase() === suffix) {
              count = parseInt(c, 10) || 1;
              break;
            }
          }

          if (count > 0) {
            lastBreach = true;
            hibpStatus.className = 'hibp-status warning';
            const tpl = lang.pw_hibp_warning || '⚠️ This password appeared in {n} data breach(es).';
            hibpStatus.textContent = tpl.replace('{n}', count.toLocaleString());
          } else {
            lastBreach = false;
            hibpStatus.className = 'hibp-status ok';
            hibpStatus.textContent = lang.pw_hibp_ok || '✓ Password not found in known data breaches.';
          }
        } catch (e) {
          // Fail-silent: do not block on API unavailability
          hibpStatus.className = 'hibp-status';
          lastBreach = false;
        }
      }

      pwInput.addEventListener('input', function() {
        clearTimeout(hibpTimer);
        hibpTimer = setTimeout(() => checkHibp(pwInput.value), 800);
      });

      // Block form submission if breach found and HIBP_BLOCK_ON_BREACH is enabled
      if (blockOnBreach && form) {
        form.addEventListener('submit', function(e) {
          if (lastBreach) {
            e.preventDefault();
            const lang = I18N[currentLang] || I18N['en'] || {};
            hibpStatus.className = 'hibp-status warning';
            hibpStatus.textContent = lang.pw_hibp_warning
              ? lang.pw_hibp_warning.replace('{n}', '?')
              : '⚠️ Please choose a different password.';
            pwInput.focus();
          }
        }, true);
      }
    })();
    <?php endif; ?>

  </script>

  <?php if (defined('COOKIE_BANNER_ENABLED') && COOKIE_BANNER_ENABLED): ?>
  <script>
    // ── Cookie Consent Banner ──────────────────────────────────────────────────
    (function () {
      const banner = document.getElementById('cookieBanner');
      if (!banner) return;
      const COOKIE_KEY = 'da_cookie_consent';

      if (localStorage.getItem(COOKIE_KEY) !== '1') {
        // Slide in after a short delay so the page settles first
        setTimeout(() => banner.classList.add('visible'), 400);
      }

      document.getElementById('cookieAcceptBtn').addEventListener('click', function () {
        localStorage.setItem(COOKIE_KEY, '1');
        banner.classList.remove('visible');
        banner.addEventListener('transitionend', () => banner.remove(), { once: true });
      });
    })();
  </script>
  <?php endif; ?>

  <?php if (defined('ACCESSIBILITY_WIDGET_ENABLED') && ACCESSIBILITY_WIDGET_ENABLED): ?>
  <script>
    // ── Accessibility Widget ───────────────────────────────────────────────────
    (function () {
      const toggleBtn  = document.getElementById('a11yToggleBtn');
      const panel      = document.getElementById('a11yPanel');
      const fontDecBtn = document.getElementById('a11yFontDec');
      const fontIncBtn = document.getElementById('a11yFontInc');
      const fontLabel  = document.getElementById('a11yFontSize');
      const contrastCb = document.getElementById('a11yContrast');
      const grayscaleCb = document.getElementById('a11yGrayscale');
      const motionCb   = document.getElementById('a11yMotion');

      const STORE = 'da_a11y';
      let state = { font: 100, contrast: false, grayscale: false, motion: false };

      try {
        const saved = JSON.parse(localStorage.getItem(STORE) || 'null');
        if (saved) state = { ...state, ...saved };
      } catch (e) {}

      function save() {
        try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) {}
      }

      function applyAll() {
        document.documentElement.style.fontSize = state.font + '%';
        fontLabel.textContent = state.font + '%';
        document.documentElement.classList.toggle('a11y-contrast', state.contrast);
        document.documentElement.classList.toggle('a11y-grayscale', state.grayscale);
        document.documentElement.classList.toggle('a11y-motion', state.motion);
        contrastCb.checked  = state.contrast;
        grayscaleCb.checked = state.grayscale;
        motionCb.checked    = state.motion;
      }

      // Inject global a11y CSS rules once
      if (!document.getElementById('a11y-rules')) {
        const style = document.createElement('style');
        style.id = 'a11y-rules';
        style.textContent = [
          '.a11y-contrast { filter: contrast(1.6) brightness(1.05); }',
          '.a11y-grayscale { filter: grayscale(1); }',
          '.a11y-contrast.a11y-grayscale { filter: contrast(1.6) brightness(1.05) grayscale(1); }',
          '.a11y-motion *, .a11y-motion *::before, .a11y-motion *::after { animation-duration: 0.001ms !important; transition-duration: 0.001ms !important; }'
        ].join('\n');
        document.head.appendChild(style);
      }

      applyAll();

      // Toggle panel
      toggleBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        const open = panel.classList.toggle('open');
        toggleBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      });

      // Close on outside click
      document.addEventListener('click', function (e) {
        const widget = document.getElementById('a11yWidget');
        if (widget && !widget.contains(e.target)) {
          panel.classList.remove('open');
          toggleBtn.setAttribute('aria-expanded', 'false');
        }
      });

      // Font size
      fontDecBtn.addEventListener('click', function () {
        state.font = Math.max(80, state.font - 10);
        applyAll(); save();
      });
      fontIncBtn.addEventListener('click', function () {
        state.font = Math.min(150, state.font + 10);
        applyAll(); save();
      });

      // Toggles
      contrastCb.addEventListener('change', function () {
        state.contrast = this.checked;
        applyAll(); save();
      });
      grayscaleCb.addEventListener('change', function () {
        state.grayscale = this.checked;
        applyAll(); save();
      });
      motionCb.addEventListener('change', function () {
        state.motion = this.checked;
        applyAll(); save();
      });
    })();
  </script>
  <?php endif; ?>
</body>

</html>