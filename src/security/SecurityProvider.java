package security;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Kryptos SecurityProvider: Håndterer AES-kryptering og HMAC-signering.
 * Dette er fundamentet for sikker kommunikasjon i prosjektet.
 */
public class SecurityProvider {
    private static final String AES_ALGO = "AES/CBC/PKCS5Padding";
    private static final String HMAC_ALGO = "HmacSHA256";

    private SecretKeySpec aesKey;
    private SecretKeySpec hmacKey;

    public SecurityProvider(byte[] aesRaw, byte[] hmacRaw) {
        this.aesKey = new SecretKeySpec(aesRaw, "AES");
        this.hmacKey = new SecretKeySpec(hmacRaw, HMAC_ALGO);
    }

    /**
     * Krypterer en klartekst-streng og returnerer Base64-kodet pakke med IV.
     */
    public String encrypt(String plainText) throws Exception {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        
        // Vi slår sammen IV og kryptert data for enkel transport
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Dekrypterer en Base64-kodet pakke (IV + Data).
     */
    public String decrypt(String encryptedBase64) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedBase64);
        
        // Pakker ut IV (de første 16 bytene)
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[combined.length - 16];
        System.arraycopy(combined, 0, iv, 0, 16);
        System.arraycopy(combined, 16, encrypted, 0, encrypted.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        return new String(cipher.doFinal(encrypted));
    }

    /**
     * Genererer en kryptografisk signatur (HMAC) av dataene.
     */
    public String generateSignature(String data) throws Exception {
        Mac sha256_HMAC = Mac.getInstance(HMAC_ALGO);
        sha256_HMAC.init(hmacKey);
        byte[] sig = sha256_HMAC.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(sig);
    }

    /**
     * Verifiserer at en signatur er gyldig for gitte data.
     */
    public boolean verifySignature(String data, String providedSignature) throws Exception {
        String expectedSignature = generateSignature(data);
        return expectedSignature.equals(providedSignature);
    }
}