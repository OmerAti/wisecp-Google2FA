<link rel="stylesheet" href="<?php echo htmlspecialchars($dir_link, ENT_QUOTES, 'UTF-8'); ?>assets/google2fa.css">
<style>
    #g2fa-verify-form { max-width: 460px; margin-top: 18px; }
    #g2fa-verify-form .g2fa-field { max-width: 420px; margin-bottom: 12px; }
    #g2fa-verify-form .g2fa-code-input { display: block !important; width: 100% !important; max-width: 420px !important; height: 42px !important; border: 1px solid #cdd8e2 !important; border-radius: 4px !important; padding: 8px 10px !important; box-sizing: border-box !important; }
    #g2fa-verify-form .g2fa-check { display: flex !important; align-items: center !important; gap: 8px !important; max-width: 420px !important; margin: 8px 0 16px !important; }
    #g2fa-verify-form .g2fa-check input[type="checkbox"] { appearance: auto !important; -webkit-appearance: checkbox !important; display: inline-block !important; position: static !important; float: none !important; width: 16px !important; height: 16px !important; margin: 0 !important; opacity: 1 !important; visibility: visible !important; transform: none !important; flex: 0 0 16px !important; }
    #g2fa-verify-form .g2fa-submit { display: inline-flex !important; align-items: center !important; justify-content: center !important; width: auto !important; min-width: 150px !important; max-width: 220px !important; height: 42px !important; padding: 0 26px !important; border: 0 !important; border-radius: 4px !important; background: #85c443 !important; color: #fff !important; font-weight: 700 !important; cursor: pointer !important; }
</style>
<div class="g2fa-wrap g2fa-verify-wrap">
    <?php if (!empty($message['text'])): ?>
        <div class="g2fa-alert <?php echo htmlspecialchars($message['type'], ENT_QUOTES, 'UTF-8'); ?>">
            <?php echo htmlspecialchars($message['text'], ENT_QUOTES, 'UTF-8'); ?>
        </div>
    <?php endif; ?>

    <div class="g2fa-panel g2fa-verify-panel">
        <h2>2FA Giris</h2>
        <p class="g2fa-copy">Devam etmek icin authenticator uygulamanizdaki 6 haneli kodu veya kurtarma kodlarinizdan birini girin.</p>

        <form id="g2fa-verify-form" class="g2fa-verify-form" method="post" action="<?php echo htmlspecialchars($link, ENT_QUOTES, 'UTF-8'); ?>?action=verify">
            <input type="hidden" name="token" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="g2fa_action" value="verify_login">

            <div class="g2fa-field">
                <label for="g2fa-code">Dogrulama veya Kurtarma Kodu</label>
                <input id="g2fa-code" class="g2fa-code-input" type="text" name="code" autocomplete="one-time-code" inputmode="numeric" required autofocus>
            </div>

            <div class="g2fa-check">
                <input id="g2fa-remember-device" type="checkbox" name="remember_device" value="1">
                <span>Bu cihazi 1 ay hatirla</span>
            </div>

            <div class="g2fa-actions">
                <button class="g2fa-submit" type="submit">Dogrula</button>
            </div>
        </form>
    </div>
</div>
