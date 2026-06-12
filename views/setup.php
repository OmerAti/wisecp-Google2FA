<link rel="stylesheet" href="<?php echo htmlspecialchars($dir_link, ENT_QUOTES, 'UTF-8'); ?>assets/google2fa.css">
<div class="g2fa-wrap g2fa-setup-wrap">
    <?php if (!empty($message['text'])): ?>
        <div class="g2fa-alert <?php echo htmlspecialchars($message['type'], ENT_QUOTES, 'UTF-8'); ?>">
            <?php echo htmlspecialchars($message['text'], ENT_QUOTES, 'UTF-8'); ?>
        </div>
    <?php endif; ?>

    <div class="g2fa-modal">
        <div class="g2fa-modal-head">
            <div>
                <span class="g2fa-badge">Guvenlik Uyarisi</span>
                <h2>2FA Giris Kurulumu</h2>
            </div>
            <a class="g2fa-close" href="<?php echo htmlspecialchars($link, ENT_QUOTES, 'UTF-8'); ?>" aria-label="Kapat">x</a>
        </div>

        <div class="g2fa-notice">
            Hesabiniza girislerde ek guvenlik icin Google Authenticator veya uyumlu bir uygulama ile QR kodu taratin.
        </div>

        <div class="g2fa-grid">
            <div class="g2fa-qr-box">
                <img class="g2fa-qr" src="<?php echo htmlspecialchars($qr_url, ENT_QUOTES, 'UTF-8'); ?>" alt="2FA QR Code">
                <div class="g2fa-app-links">
                    <a class="g2fa-store" href="<?php echo htmlspecialchars($app_links['apple'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener">Apple Store</a>
                    <a class="g2fa-store" href="<?php echo htmlspecialchars($app_links['google'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener">Google Play</a>
                </div>
            </div>

            <div>
                <p class="g2fa-copy">Authenticator uygulamanizda QR kodu taratin. QR okunmazsa asagidaki anahtari elle girin.</p>
                <div class="g2fa-secret"><?php echo htmlspecialchars($pending_secret, ENT_QUOTES, 'UTF-8'); ?></div>

                <form class="g2fa-form" method="post" action="<?php echo htmlspecialchars($link, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="token" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="g2fa_action" value="enable">
                    <label>Uygulamadaki 6 haneli kod</label>
                    <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required>
                    <div class="g2fa-actions">
                        <a class="button btn btn-secondary" href="<?php echo htmlspecialchars($link, ENT_QUOTES, 'UTF-8'); ?>">Vazgec</a>
                        <button class="button btn btn-primary" type="submit">Dogrula ve Etkinlestir</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
