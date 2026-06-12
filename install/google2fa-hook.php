<?php
if (!function_exists('google2fa_global_client_id')) {
    function google2fa_global_client_id()
    {
        if (class_exists('UserManager') && method_exists('UserManager', 'LoginData')) {
            try {
                $id = UserManager::LoginData("id");
                if ($id) return (int) $id;

                $data = UserManager::LoginData();
                $id = google2fa_global_extract_id($data);
                if ($id) return $id;
            } catch (Exception $e) {
            } catch (Throwable $e) {
            }
        }

        $sources = [isset($_SESSION) ? $_SESSION : []];
        foreach ($sources as $source) {
            $id = google2fa_global_extract_id($source);
            if ($id) return $id;
        }

        return 0;
    }
}

if (!function_exists('google2fa_global_extract_id')) {
    function google2fa_global_extract_id($source, $depth = 0)
    {
        if ($depth > 3 || !$source) return 0;
        if (is_object($source)) $source = get_object_vars($source);
        if (!is_array($source)) return 0;

        foreach (['id', 'user_id', 'client_id', 'owner_id', 'member_id'] as $key) {
            if (isset($source[$key]) && is_numeric($source[$key]) && (int) $source[$key] > 0) {
                return (int) $source[$key];
            }
        }

        foreach (['user', 'client', 'Client', 'User', 'login', 'account', 'member'] as $key) {
            if (isset($source[$key])) {
                $id = google2fa_global_extract_id($source[$key], $depth + 1);
                if ($id) return $id;
            }
        }

        return 0;
    }
}

if (!function_exists('google2fa_global_enabled')) {
    function google2fa_global_enabled($clientId)
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

if (!function_exists('google2fa_global_base_path')) {
    function google2fa_global_base_path()
    {
        $script = isset($_SERVER['SCRIPT_NAME']) ? str_replace('\\', '/', $_SERVER['SCRIPT_NAME']) : '';
        $dir = trim(str_replace('/index.php', '', $script), '/');
        return $dir ? '/' . $dir : '';
    }
}

if (!function_exists('google2fa_global_fingerprint')) {
    function google2fa_global_fingerprint($clientId)
    {
        return hash('sha256', session_id() . '|' . (int) $clientId);
    }
}

if (!function_exists('google2fa_global_remember_cookie_name')) {
    function google2fa_global_remember_cookie_name($clientId)
    {
        return 'google2fa_remember_' . (int) $clientId;
    }
}

if (!function_exists('google2fa_global_remember_key')) {
    function google2fa_global_remember_key()
    {
        return hash('sha256', 'Google2FA|OmerAti|');
    }
}

if (!function_exists('google2fa_global_remember_hash')) {
    function google2fa_global_remember_hash($clientId, $expires)
    {
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        return hash_hmac('sha256', $clientId . '|' . $expires . '|' . $ua, google2fa_global_remember_key());
    }
}

if (!function_exists('google2fa_global_remember_valid')) {
    function google2fa_global_remember_valid($clientId)
    {
        $name = google2fa_global_remember_cookie_name($clientId);
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

        return hash_equals(google2fa_global_remember_hash($clientId, $expires), $parts[1]);
    }
}

if (!function_exists('google2fa_global_verified')) {
    function google2fa_global_verified($clientId)
    {
        if (google2fa_global_remember_valid($clientId)) {
            return true;
        }

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

        return hash_equals($verified['fingerprint'], google2fa_global_fingerprint($clientId));
    }
}

if (!function_exists('google2fa_global_redirect_output')) {
    function google2fa_global_redirect_output()
    {
        $clientId = google2fa_global_client_id();
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $basePath = google2fa_global_base_path();
        $verifyUrl = $basePath . '/addon/Google2FA?action=verify';
        $isGoogle2FA = strpos($uri, '/addon/Google2FA') !== false;
        $verified = $clientId && google2fa_global_verified($clientId);
        $enabled = $clientId && google2fa_global_enabled($clientId);

        if ($clientId && !$isGoogle2FA && !$verified && $enabled) {
            if (!headers_sent()) {
                header('Location: ' . $verifyUrl);
                exit;
            }
            return '<script>window.location.replace("' . $verifyUrl . '");</script>';
        }

        return '';
    }
}

Hook::add("ClientAreaHeadMetaTags", 1, function () {
    return google2fa_global_redirect_output();
});

Hook::add("ClientAreaHeadJS", 1, function () {
    return google2fa_global_redirect_output();
});

Hook::add("ClientAreaBeginBody", 1, function () {
    return google2fa_global_redirect_output();
});

Hook::add("ClientAreaEndBody", 1, function () {
    return google2fa_global_redirect_output();
});
