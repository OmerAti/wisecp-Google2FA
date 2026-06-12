<?php

class Google2FA extends AddonModule
{
    public $version = "1.0.0";
    private $table = "mod_google2fa_clients";

    public function __construct()
    {
        $this->_name = __CLASS__;
        parent::__construct();
    }

    public function fields()
    {
        $settings = isset($this->config["settings"]) ? $this->config["settings"] : [];

        return [
            'issuer' => [
                'wrap_width'  => 100,
                'name'        => 'Authenticator Issuer',
                'description' => 'Google Authenticator uygulamasinda gorunecek servis adi.',
                'type'        => 'text',
                'value'       => isset($settings['issuer']) ? $settings['issuer'] : 'WISECP',
                'placeholder' => 'WISECP',
            ],
            'enforce_after_login' => [
                'wrap_width'  => 100,
                'name'        => 'Login Sonrasi Zorunlu Dogrulama',
                'description' => '2FA etkin musteriler dogrulama yapmadan musteri panelini kullanamaz.',
                'type'        => 'approval',
                'checked'     => !isset($settings['enforce_after_login']) || $settings['enforce_after_login'],
            ],
            'time_window' => [
                'wrap_width'  => 100,
                'name'        => 'Zaman Toleransi',
                'description' => '0 yalniz mevcut 30 saniyelik kodu, 1 onceki/sonraki kodu da kabul eder.',
                'type'        => 'dropdown',
                'options'     => ['0' => '0', '1' => '1', '2' => '2'],
                'value'       => isset($settings['time_window']) ? (string) $settings['time_window'] : '1',
            ],
            'encryption_key' => [
                'wrap_width'  => 100,
                'name'        => 'Sifreleme Anahtari',
                'description' => 'Secret verilerini sifrelemek icin kullanilir. Bos birakilirsa kurulum yolundan yerel anahtar uretilir.',
                'type'        => 'password',
                'value'       => isset($settings['encryption_key']) ? $settings['encryption_key'] : '',
                'placeholder' => 'Rastgele guclu bir anahtar girin',
            ],
        ];
    }

    public function save_fields($fields = [])
    {
        $fields['issuer'] = isset($fields['issuer']) && trim($fields['issuer']) ? trim($fields['issuer']) : 'WISECP';
        $fields['enforce_after_login'] = isset($fields['enforce_after_login']) && $fields['enforce_after_login'] ? true : false;
        $fields['time_window'] = isset($fields['time_window']) && in_array((string) $fields['time_window'], ['0', '1', '2'], true) ? (string) $fields['time_window'] : '1';
        $fields['encryption_key'] = isset($fields['encryption_key']) ? trim($fields['encryption_key']) : '';

        return $fields;
    }

    public function activate()
    {
        $this->installGlobalHook();
        return true;
    }

    public function deactivate()
    {
        $this->removeGlobalHook();
        return true;
    }

    public function adminArea()
    {
        $this->ensureTable();
        if ($this->globalHookPath()) {
            $this->installGlobalHook();
        }

        $action = Filter::init("REQUEST/action", "route");
        if (!$action || !in_array($action, ['admin'], true)) {
            $action = 'admin';
        }

        $stats = $this->stats();
        $variables = [
            'link'     => $this->area_link,
            'dir_link' => $this->url,
            'stats'    => $stats,
            'fields'   => $this->fields(),
            'settings' => isset($this->config['settings']) ? $this->config['settings'] : [],
            'hook_installed' => $this->globalHookPath() ? is_file($this->globalHookPath()) : false,
            'hook_path' => $this->globalHookPath(),
        ];

        return [
            'page_title'  => '2FA Giriş',
            'breadcrumbs' => [
                ['link' => '', 'title' => '2FA Giriş'],
            ],
            'content'     => $this->view($action . ".php", $variables),
        ];
    }

    public function clientArea()
    {
        $this->ensureTable();
        $clientId = $this->clientId();

        $action = Filter::init("REQUEST/action", "route");
        if (!$action) {
            $action = 'index';
        }
        if (!in_array($action, ['index', 'setup', 'verify'], true)) {
            $action = 'index';
        }

        $message = ['type' => '', 'text' => ''];
        $authMissing = !$clientId;
        if ($authMissing) {
            $message = ['type' => 'error', 'text' => 'Musteri oturumu bulunamadi. Lutfen tekrar giris yapin.'];
        }

        $record = $clientId ? $this->record($clientId) : [];
        $showCodes = [];

        if (!$authMissing && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $postedAction = Filter::init("POST/g2fa_action", "route");
            if (!$this->checkCsrf(Filter::init("POST/token", "text"))) {
                $message = ['type' => 'error', 'text' => $this->t('csrf_error')];
            } elseif ($postedAction === 'enable') {
                $result = $this->enable($record);
                $message = $result['message'];
                $showCodes = isset($result['codes']) ? $result['codes'] : [];
                $record = $this->record($clientId);
                if ($message['type'] === 'success') {
                    $action = 'index';
                }
            } elseif ($postedAction === 'verify_login') {
                $message = $this->verifyLogin($record);
                $record = $this->record($clientId);
                if ($message['type'] === 'success') {
                    $this->redirectAfterVerify();
                }
            } elseif ($postedAction === 'disable') {
                $message = $this->disable($record);
                $record = $this->record($clientId);
                if ($message['type'] === 'success') {
                    $action = 'index';
                }
            } elseif ($postedAction === 'regenerate') {
                $result = $this->regenerateRecoveryCodes($record);
                $message = $result['message'];
                $showCodes = isset($result['codes']) ? $result['codes'] : [];
                $record = $this->record($clientId);
                if ($message['type'] === 'success') {
                    $action = 'index';
                }
            }
        }

        $mustVerify = !$authMissing && $this->isEnabled($record) && !$this->sessionVerified();
        if ($mustVerify) {
            $action = 'verify';
        }

        if (!$authMissing && $action === 'setup' && !$this->isEnabled($record)) {
            $pending = $this->pendingSecret($record);
            $record = $this->record($clientId);
        } else {
            $pending = '';
        }

        $variables = [
            'link'           => $this->area_link,
            'dir_link'       => $this->url,
            'token'          => $this->csrf(),
            'message'        => $message,
            'record'         => $record,
            'enabled'        => $this->isEnabled($record),
            'must_verify'    => $mustVerify,
            'pending_secret' => $pending,
            'otpauth_url'    => $pending ? $this->otpAuthUrl($pending) : '',
            'qr_url'         => $pending ? $this->qrUrl($this->otpAuthUrl($pending)) : '',
            'app_links'      => [
                'apple'  => 'https://apps.apple.com/app/google-authenticator/id388497605',
                'google' => 'https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2',
            ],
            'show_codes'     => $showCodes,
            'auth_missing'    => $authMissing,
            'user'           => isset($this->user) ? $this->user : [],
            'lang'           => isset($this->lang) ? $this->lang : [],
        ];

        return [
            'use_with_theme' => true,
            'page_title'  => $this->t('title'),
            'breadcrumbs' => [
                ['link' => '', 'title' => 'Hesabim'],
                ['link' => '', 'title' => $this->t('security')],
                ['link' => '', 'title' => $this->t('title')],
            ],
            'content'     => $this->view($action . ".php", $variables),
        ];
    }

    public function main()
    {
        return $this->clientArea();
    }

    private function enable($record)
    {
        $code = preg_replace('/\D+/', '', (string) Filter::init("POST/code", "numbers"));
        $pending = isset($record['pending_secret']) ? $this->decrypt($record['pending_secret']) : '';

        if (!$pending || !$this->verifyTotp($pending, $code)) {
            return ['message' => ['type' => 'error', 'text' => $this->t('invalid_code')]];
        }

        $codes = $this->makeRecoveryCodes();
        $set = [
            'secret'          => $this->encrypt($pending),
            'pending_secret'  => '',
            'enabled'         => 1,
            'recovery_hashes' => json_encode(array_map('password_hash', $codes, array_fill(0, count($codes), PASSWORD_DEFAULT))),
            'updated_at'      => date('Y-m-d H:i:s'),
            'verified_at'     => date('Y-m-d H:i:s'),
        ];

        $this->saveRecord($this->clientId(), $set);
        $this->markSessionVerified();

        return [
            'message' => ['type' => 'success', 'text' => $this->t('enabled_success')],
            'codes'   => $codes,
        ];
    }

    private function verifyLogin($record)
    {
        $code = strtoupper(trim((string) Filter::init("POST/code", "text")));
        $remember = Filter::init("POST/remember_device", "numbers") ? true : false;
        if (!$this->isEnabled($record)) {
            return ['type' => 'error', 'text' => $this->t('invalid_code')];
        }

        $secret = $this->decrypt($record['secret']);
        if ($this->verifyTotp($secret, preg_replace('/\D+/', '', $code))) {
            $this->markSessionVerified($remember);
            return ['type' => 'success', 'text' => $this->t('verified_success')];
        }

        if ($this->consumeRecoveryCode($record, $code)) {
            $this->markSessionVerified($remember);
            return ['type' => 'success', 'text' => $this->t('verified_success')];
        }

        return ['type' => 'error', 'text' => $this->t('invalid_code')];
    }

    private function redirectAfterVerify()
    {
        $target = $this->clientHomeUrl();
        if (!headers_sent()) {
            header('Location: ' . $target);
            exit;
        }
        echo '<script>window.location.replace("' . htmlspecialchars($target, ENT_QUOTES, 'UTF-8') . '");</script>';
        exit;
    }

    private function clientHomeUrl()
    {
        $script = isset($_SERVER['SCRIPT_NAME']) ? str_replace('\\', '/', $_SERVER['SCRIPT_NAME']) : '';
        $base = trim(str_replace('/index.php', '', $script), '/');
        return ($base ? '/' . $base : '') . '/anasayfa';
    }

    private function disable($record)
    {
        $code = preg_replace('/\D+/', '', (string) Filter::init("POST/code", "numbers"));
        $secret = $this->isEnabled($record) ? $this->decrypt($record['secret']) : '';

        if (!$secret || !$this->verifyTotp($secret, $code)) {
            return ['type' => 'error', 'text' => $this->t('invalid_code')];
        }

        $this->saveRecord($this->clientId(), [
            'secret'          => '',
            'pending_secret'  => '',
            'enabled'         => 0,
            'recovery_hashes' => '',
            'updated_at'      => date('Y-m-d H:i:s'),
        ]);
        unset($_SESSION['google2fa_verified_client_' . $this->clientId()]);

        return ['type' => 'success', 'text' => $this->t('disabled_success')];
    }

    private function regenerateRecoveryCodes($record)
    {
        $code = preg_replace('/\D+/', '', (string) Filter::init("POST/code", "numbers"));
        $secret = $this->isEnabled($record) ? $this->decrypt($record['secret']) : '';

        if (!$secret || !$this->verifyTotp($secret, $code)) {
            return ['message' => ['type' => 'error', 'text' => $this->t('invalid_code')]];
        }

        $codes = $this->makeRecoveryCodes();
        $this->saveRecord($this->clientId(), [
            'recovery_hashes' => json_encode(array_map('password_hash', $codes, array_fill(0, count($codes), PASSWORD_DEFAULT))),
            'updated_at'      => date('Y-m-d H:i:s'),
        ]);

        return [
            'message' => ['type' => 'success', 'text' => $this->t('recovery_codes')],
            'codes'   => $codes,
        ];
    }

    private function pendingSecret($record)
    {
        if (isset($record['pending_secret']) && $record['pending_secret']) {
            return $this->decrypt($record['pending_secret']);
        }

        $secret = $this->randomBase32(32);
        $this->saveRecord($this->clientId(), [
            'pending_secret' => $this->encrypt($secret),
            'updated_at'     => date('Y-m-d H:i:s'),
        ]);

        return $secret;
    }

    private function record($clientId)
    {
        $query = WDB::select("*");
        $query->from($this->table);
        $query->where("user_id", "=", (int) $clientId);
        if ($query->build()) {
            $rows = WDB::fetch_assoc();
            if ($rows && isset($rows[0])) {
                return $rows[0];
            }
        }

        return [];
    }

    private function saveRecord($clientId, array $set)
    {
        $record = $this->record($clientId);
        if ($record) {
            $operation = WDB::update($this->table);
            $operation->set($set);
            $operation->where("user_id", "=", (int) $clientId);
            return $operation->save();
        }

        $set['user_id'] = (int) $clientId;
        if (!isset($set['created_at'])) {
            $set['created_at'] = date('Y-m-d H:i:s');
        }
        return WDB::insert($this->table, $set);
    }

    private function consumeRecoveryCode($record, $code)
    {
        $hashes = isset($record['recovery_hashes']) && $record['recovery_hashes'] ? json_decode($record['recovery_hashes'], true) : [];
        if (!$hashes || !is_array($hashes)) {
            return false;
        }

        foreach ($hashes as $idx => $hash) {
            if (password_verify($code, $hash)) {
                unset($hashes[$idx]);
                $this->saveRecord($this->clientId(), [
                    'recovery_hashes' => json_encode(array_values($hashes)),
                    'updated_at'      => date('Y-m-d H:i:s'),
                ]);
                return true;
            }
        }

        return false;
    }

    private function isEnabled($record)
    {
        return isset($record['enabled']) && (int) $record['enabled'] === 1 && !empty($record['secret']);
    }

    private function sessionVerified()
    {
        if ($this->rememberCookieValid($this->clientId())) {
            return true;
        }

        $key = 'google2fa_verified_client_' . $this->clientId();
        if (empty($_SESSION[$key]) || !is_array($_SESSION[$key])) {
            return false;
        }

        $verified = $_SESSION[$key];
        if (empty($verified['time']) || empty($verified['fingerprint'])) {
            return false;
        }

        if ((time() - (int) $verified['time']) > 43200) {
            unset($_SESSION[$key]);
            return false;
        }

        return hash_equals($verified['fingerprint'], $this->sessionFingerprint());
    }

    private function markSessionVerified($remember = false)
    {
        $_SESSION['google2fa_verified_client_' . $this->clientId()] = [
            'time'        => time(),
            'fingerprint' => $this->sessionFingerprint(),
        ];

        if ($remember) {
            $this->setRememberCookie($this->clientId());
        }
    }

    private function sessionFingerprint()
    {
        return hash('sha256', session_id() . '|' . $this->clientId());
    }

    private function rememberCookieValid($clientId)
    {
        $name = $this->rememberCookieName($clientId);
        if (!$clientId || empty($_COOKIE[$name])) {
            return false;
        }

        $parts = explode('|', $_COOKIE[$name], 2);
        if (count($parts) !== 2 || !ctype_digit($parts[0])) {
            return false;
        }

        $expires = (int) $parts[0];
        if ($expires < time()) {
            return false;
        }

        return hash_equals($this->rememberCookieHash($clientId, $expires), $parts[1]);
    }

    private function setRememberCookie($clientId)
    {
        $expires = time() + (86400 * 30);
        $value = $expires . '|' . $this->rememberCookieHash($clientId, $expires);
        setcookie($this->rememberCookieName($clientId), $value, $expires, '/', '', $this->isHttps(), true);
        $_COOKIE[$this->rememberCookieName($clientId)] = $value;
    }

    private function rememberCookieName($clientId)
    {
        return 'google2fa_remember_' . (int) $clientId;
    }

    private function rememberCookieHash($clientId, $expires)
    {
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        return hash_hmac('sha256', $clientId . '|' . $expires . '|' . $ua, $this->rememberCookieKey());
    }

    private function rememberCookieKey()
    {
        return hash('sha256', 'Google2FA|OmerAti|');
    }

    private function isHttps()
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443);
    }

    private function clientId()
    {
        $sources = [];

        if (isset($this->user)) {
            $sources[] = $this->user;
        }
        if (isset($this->client)) {
            $sources[] = $this->client;
        }
        if (isset($_SESSION)) {
            $sources[] = $_SESSION;
        }

        foreach ($sources as $source) {
            $id = $this->extractId($source);
            if ($id) {
                return $id;
            }
        }

        if (class_exists('UserManager') && method_exists('UserManager', 'LoginData')) {
            $id = UserManager::LoginData("id");
            if ($id) {
                return (int) $id;
            }
        }

        return 0;
    }

    private function extractId($source, $depth = 0)
    {
        if ($depth > 3 || !$source) {
            return 0;
        }

        if (is_object($source)) {
            $source = get_object_vars($source);
        }

        if (!is_array($source)) {
            return 0;
        }

        foreach (['id', 'user_id', 'client_id', 'owner_id', 'member_id'] as $key) {
            if (isset($source[$key]) && is_numeric($source[$key]) && (int) $source[$key] > 0) {
                return (int) $source[$key];
            }
        }

        foreach (['user', 'client', 'Client', 'User', 'login', 'account', 'member'] as $key) {
            if (isset($source[$key])) {
                $id = $this->extractId($source[$key], $depth + 1);
                if ($id) {
                    return $id;
                }
            }
        }

        return 0;
    }

    private function ensureTable()
    {
        if (WDB::hasTable($this->table)) {
            return;
        }

        WDB::exec("CREATE TABLE `" . $this->table . "` (
            `id` INT(11) NOT NULL AUTO_INCREMENT,
            `user_id` INT(11) NOT NULL,
            `secret` TEXT NULL,
            `pending_secret` TEXT NULL,
            `enabled` TINYINT(1) NOT NULL DEFAULT 0,
            `recovery_hashes` TEXT NULL,
            `created_at` DATETIME NULL,
            `updated_at` DATETIME NULL,
            `verified_at` DATETIME NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `user_id` (`user_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;");
    }

    private function installGlobalHook()
    {
        $source = rtrim($this->dir, '/\\') . "/install/google2fa-hook.php";
        $target = $this->globalHookPath();

        if (!$target || !is_file($source)) {
            return false;
        }

        $directory = dirname($target);
        if (!is_dir($directory) || !is_writable($directory)) {
            return false;
        }

        return copy($source, $target);
    }

    private function removeGlobalHook()
    {
        $target = $this->globalHookPath();
        if ($target && is_file($target)) {
            @unlink($target);
        }
        return true;
    }

    private function globalHookPath()
    {
        if (empty($this->dir)) {
            return '';
        }

        $dir = rtrim(str_replace('\\', '/', $this->dir), '/');
        $coremio = dirname(dirname(dirname($dir)));
        return $coremio . "/hooks/google2fa.php";
    }

    private function stats()
    {
        $enabled = 0;
        $total = 0;
        $query = WDB::select("enabled");
        $query->from($this->table);
        if ($query->build()) {
            $rows = WDB::fetch_assoc();
            foreach ($rows as $row) {
                $total++;
                if ((int) $row['enabled'] === 1) {
                    $enabled++;
                }
            }
        }

        return ['total' => $total, 'enabled' => $enabled, 'disabled' => max(0, $total - $enabled)];
    }

    private function verifyTotp($secret, $code)
    {
        if (!preg_match('/^\d{6}$/', $code)) {
            return false;
        }

        $window = isset($this->config['settings']['time_window']) ? (int) $this->config['settings']['time_window'] : 1;
        $timeSlice = floor(time() / 30);
        for ($i = -$window; $i <= $window; $i++) {
            if (hash_equals($this->totp($secret, $timeSlice + $i), $code)) {
                return true;
            }
        }

        return false;
    }

    private function totp($secret, $timeSlice)
    {
        $secretKey = $this->base32Decode($secret);
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $timeSlice);
        $hm = hash_hmac('sha1', $time, $secretKey, true);
        $offset = ord(substr($hm, -1)) & 0x0F;
        $hashpart = substr($hm, $offset, 4);
        $value = unpack('N', $hashpart);
        $value = $value[1] & 0x7FFFFFFF;

        return str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);
    }

    private function base32Decode($base32)
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $base32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $base32));
        $bits = '';
        $output = '';

        for ($i = 0; $i < strlen($base32); $i++) {
            $value = strpos($alphabet, $base32[$i]);
            if ($value === false) {
                continue;
            }
            $bits .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
        }

        for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
            $output .= chr(bindec(substr($bits, $i, 8)));
        }

        return $output;
    }

    private function randomBase32($length)
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bytes = random_bytes($length);
        $secret = '';
        for ($i = 0; $i < $length; $i++) {
            $secret .= $alphabet[ord($bytes[$i]) % 32];
        }
        return $secret;
    }

    private function makeRecoveryCodes()
    {
        $codes = [];
        for ($i = 0; $i < 8; $i++) {
            $codes[] = strtoupper(substr(bin2hex(random_bytes(5)), 0, 5) . '-' . substr(bin2hex(random_bytes(5)), 0, 5));
        }
        return $codes;
    }

    private function otpAuthUrl($secret)
    {
        $issuer = isset($this->config['settings']['issuer']) && $this->config['settings']['issuer'] ? $this->config['settings']['issuer'] : 'WISECP';
        $label = $issuer . ':' . (isset($this->user['email']) ? $this->user['email'] : $this->clientId());

        return 'otpauth://totp/' . rawurlencode($label) . '?secret=' . rawurlencode($secret) . '&issuer=' . rawurlencode($issuer) . '&digits=6&period=30&algorithm=SHA1';
    }

    private function qrUrl($otpauth)
    {
        return 'https://api.qrserver.com/v1/create-qr-code/?size=260x260&margin=12&data=' . rawurlencode($otpauth);
    }

    private function encrypt($plain)
    {
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($plain, 'AES-256-CBC', $this->key(), OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $cipher);
    }

    private function decrypt($payload)
    {
        if (!$payload) {
            return '';
        }
        $raw = base64_decode($payload, true);
        if ($raw === false || strlen($raw) < 17) {
            return '';
        }
        $iv = substr($raw, 0, 16);
        $cipher = substr($raw, 16);
        $plain = openssl_decrypt($cipher, 'AES-256-CBC', $this->key(), OPENSSL_RAW_DATA, $iv);
        return $plain === false ? '' : $plain;
    }

    private function key()
    {
        $configured = isset($this->config['settings']['encryption_key']) ? $this->config['settings']['encryption_key'] : '';
        if (!$configured) {
            $configured = __DIR__ . '|google2fa-local-key';
        }
        return hash('sha256', $configured, true);
    }

    private function csrf()
    {
        if (empty($_SESSION['google2fa_csrf'])) {
            $_SESSION['google2fa_csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['google2fa_csrf'];
    }

    private function checkCsrf($token)
    {
        return isset($_SESSION['google2fa_csrf']) && hash_equals($_SESSION['google2fa_csrf'], (string) $token);
    }

    private function t($key)
    {
        $fallback = [
            'title'            => '2FA Giriş',
            'security'         => 'Hesabım',
            'enabled'          => 'Etkin',
            'disabled'         => 'Devre Dışı',
            'setup'            => 'Kurulumu Başlat',
            'verify'           => 'Doğrula',
            'disable'          => 'Devre Dışı Bırak',
            'recovery_codes'   => 'Kurtarma Kodları',
            'code'             => 'Doğrulama Kodu',
            'current_password' => 'Mevcut Şifre',
            'invalid_code'     => 'Doğrulama kodu geçersiz.',
            'invalid_password' => 'Şifre doğrulanamadı.',
            'enabled_success'  => 'İki faktör doğrulama etkinleştirildi.',
            'disabled_success' => 'İki faktör doğrulama devre dışı bırakıldı.',
            'verified_success' => 'Doğrulama tamamlandı.',
            'csrf_error'       => 'Oturum doğrulaması geçersiz. Lütfen tekrar deneyin.',
        ];

        return isset($this->lang) && isset($this->lang[$key]) ? $this->lang[$key] : (isset($fallback[$key]) ? $fallback[$key] : $key);
    }
}

if (class_exists('Hook')) {
    if (!function_exists('google2fa_hook_client_id')) {
        function google2fa_hook_client_id()
        {
            $candidates = [
                ['user', 'id'],
                ['client', 'id'],
                ['Client', 'id'],
                ['User', 'id'],
                ['login', 'id'],
            ];

            foreach ($candidates as $candidate) {
                if (isset($_SESSION[$candidate[0]]) && is_array($_SESSION[$candidate[0]]) && isset($_SESSION[$candidate[0]][$candidate[1]])) {
                    return (int) $_SESSION[$candidate[0]][$candidate[1]];
                }
            }

            return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : 0;
        }
    }

    if (!function_exists('google2fa_hook_enabled')) {
        function google2fa_hook_enabled($clientId)
        {
            if (!$clientId || !class_exists('WDB') || !WDB::hasTable('mod_google2fa_clients')) {
                return false;
            }

            $query = WDB::select("enabled");
            $query->from("mod_google2fa_clients");
            $query->where("user_id", "=", (int) $clientId);
            if ($query->build()) {
                $rows = WDB::fetch_assoc();
                if (isset($rows[0]) && is_array($rows[0])) {
                    return isset($rows[0]['enabled']) && (int) $rows[0]['enabled'] === 1;
                }
                return isset($rows['enabled']) && (int) $rows['enabled'] === 1;
            }

            return false;
        }
    }

    if (!function_exists('google2fa_hook_base_path')) {
        function google2fa_hook_base_path()
        {
            $script = isset($_SERVER['SCRIPT_NAME']) ? str_replace('\\', '/', $_SERVER['SCRIPT_NAME']) : '';
            $dir = trim(str_replace('/index.php', '', $script), '/');
            return $dir ? '/' . $dir : '';
        }
    }

    if (!function_exists('google2fa_hook_fingerprint')) {
        function google2fa_hook_fingerprint()
        {
            $data = isset($_SESSION) ? $_SESSION : [];
            foreach (array_keys($data) as $key) {
                if (strpos((string) $key, 'google2fa_') === 0) {
                    unset($data[$key]);
                }
            }

            return hash('sha256', session_id() . '|' . serialize($data));
        }
    }

    if (!function_exists('google2fa_hook_verified')) {
        function google2fa_hook_verified($clientId)
        {
            $key = 'google2fa_verified_client_' . $clientId;
            if (empty($_SESSION[$key]) || !is_array($_SESSION[$key])) {
                return false;
            }

            $verified = $_SESSION[$key];
            if (empty($verified['time']) || empty($verified['fingerprint'])) {
                return false;
            }

            if ((time() - (int) $verified['time']) > 43200) {
                unset($_SESSION[$key]);
                return false;
            }

            return hash_equals($verified['fingerprint'], google2fa_hook_fingerprint());
        }
    }

    Hook::add("ClientAreaBeginBody", 1, function () {
        $clientId = google2fa_hook_client_id();
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $basePath = google2fa_hook_base_path();
        $verifyUrl = $basePath . '/addon/Google2FA?action=verify';
        $isGoogle2FA = strpos($uri, '/addon/Google2FA') !== false;
        $verified = $clientId && google2fa_hook_verified($clientId);

        if ($clientId && !$isGoogle2FA && !$verified && google2fa_hook_enabled($clientId)) {
            if (!headers_sent()) {
                header('Location: ' . $verifyUrl);
                exit;
            }

            return '<script>window.location.href="' . $verifyUrl . '";</script>';
        }

        return '';
    });

    Hook::add("ClientAreaHeadCSS", 1, function () {
        return '<link rel="stylesheet" href="/coremio/modules/Addons/Google2FA/assets/google2fa.css">';
    });
}
