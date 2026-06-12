<div class="g2fa-wrap">
    <?php if (!empty($message['text'])): ?>
        <div class="g2fa-alert <?php echo htmlspecialchars($message['type'], ENT_QUOTES, 'UTF-8'); ?>">
            <?php echo htmlspecialchars($message['text'], ENT_QUOTES, 'UTF-8'); ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($show_codes)): ?>
        <div class="g2fa-panel">
            <h3>Kurtarma Kodlari</h3>
            <p>Bu kodlari guvenli bir yerde saklayin. Her kod yalniz bir kez kullanilabilir.</p>
            <div class="g2fa-codes">
                <?php foreach ($show_codes as $code): ?>
                    <div><?php echo htmlspecialchars($code, ENT_QUOTES, 'UTF-8'); ?></div>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endif; ?>

    <div class="g2fa-panel">
        <h2>2FA Giriş</h2>
        <p>Durum: <span class="g2fa-status <?php echo $enabled ? 'enabled' : 'disabled'; ?>"><?php echo $enabled ? 'Etkin' : 'Devre Disi'; ?></span></p>

        <?php if (!empty($auth_missing)): ?>
            <p>Musteri oturumu okunamadigi icin 2FA islemi baslatilamadi.</p>
        <?php elseif (!$enabled): ?>
            <p>Google Authenticator, Microsoft Authenticator, 1Password veya uyumlu bir TOTP uygulamasi ile hesabiniza ikinci bir dogrulama adimi ekleyebilirsiniz.</p>
            <a class="button btn btn-primary" href="<?php echo htmlspecialchars($link, ENT_QUOTES, 'UTF-8'); ?>?action=setup">Kurulumu Baslat</a>
        <?php else: ?>
            <p>Hesabiniz icin iki faktor dogrulama etkin. Yeni kurtarma kodlari olusturabilir veya dogrulamayi devre disi birakabilirsiniz.</p>

            <form method="post" action="<?php echo htmlspecialchars($link, ENT_QUOTES, 'UTF-8'); ?>" style="margin-top:16px;">
                <input type="hidden" name="token" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="g2fa_action" value="regenerate">
                <label>Dogrulama Kodu</label>
                <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required>
                <button class="button btn btn-secondary" type="submit">Kurtarma Kodlarini Yenile</button>
            </form>

            <form method="post" action="<?php echo htmlspecialchars($link, ENT_QUOTES, 'UTF-8'); ?>" style="margin-top:16px;">
                <input type="hidden" name="token" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="g2fa_action" value="disable">
                <label>Dogrulama Kodu</label>
                <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required>
                <button class="button btn btn-danger" type="submit">Devre Disi Birak</button>
            </form>
        <?php endif; ?>
    </div>
</div>
