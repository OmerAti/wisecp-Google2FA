<div class="g2fa-wrap">
    <div class="g2fa-panel">
        <h2>2FA Giriş</h2>
        <p>Bu eklenti musteri sol menusune <strong>2FA Giriş</strong> baglantisi ekler ve musterilerin TOTP tabanli iki faktor dogrulama acmasini saglar.</p>
        <ul>
            <li>Toplam kayit: <?php echo (int) $stats['total']; ?></li>
            <li>2FA etkin: <?php echo (int) $stats['enabled']; ?></li>
            <li>2FA devre disi: <?php echo (int) $stats['disabled']; ?></li>
            <li>Global hook: <?php echo !empty($hook_installed) ? 'Kurulu' : 'Kurulu degil'; ?></li>
        </ul>
        <?php if (empty($hook_installed)): ?>
            <div class="g2fa-alert error">
                2FA zorlamasi icin <code><?php echo htmlspecialchars($hook_path, ENT_QUOTES, 'UTF-8'); ?></code> dosyasi kurulmalidir.
                <code>Google2FA/install/google2fa-hook.php</code> dosyasini bu konuma kopyalayin.
            </div>
        <?php endif; ?>
    </div>

    <div class="g2fa-panel">
        <h3>Kurulum Notlari</h3>
        <p>Modul aktif edildikten sonra musteriler sol menudeki <strong>2FA Giriş</strong> baglantisindan veya <code>/addon/Google2FA</code> adresinden 2FA ayarlarini yonetebilir.</p>
        <p>Login sonrasi zorunlu dogrulama icin eklenti ana dosyasindaki client-area hook'u kullanilir. Tema menusu farkliysa sol menunuzde ayni adla elle link verebilirsiniz.</p>
    </div>
</div>
