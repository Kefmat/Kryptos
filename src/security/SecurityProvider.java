package security;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Arrays;

/**
 * SecurityProvider: Traffic Padding for å hindre sidekanal-angrep.
 * Alle pakker polstres til en fast størrelse før de krypteres.
 */
public class SecurityProvider {
    private static final String AES_ALGO = "AES/CBC/PKCS5Padding";
    private static final int CONSTANT_PACKET_SIZE = 256; 

    private SecretKeySpec aesKey;
    private SecretKeySpec hmacKey;
    private SecureRandom random = new SecureRandom();

    public SecurityProvider(byte[] aesRaw, byte[] hmacRaw) {
        this.aesKey = new SecretKeySpec(aesRaw, "AES");
        this.hmacKey = new SecretKeySpec(hmacRaw, "HmacSHA256");
    }

    /**
     * Krypterer data og polstrer den til CONSTANT_PACKET_SIZE.
     */
    public String encrypt(String plainText) throws Exception {
        byte[] data = plainText.getBytes();
        
        // En buffer med fast størrelse og fyll med tilfeldig støy
        byte[] paddedData = new byte[CONSTANT_PACKET_SIZE];
        random.nextBytes(paddedData);
        
        // Legg inn lengden på den faktiske meldingen i første byte (enkelt format)
        // Bruker 2 bytes for lengde for å være trygge
        if (data.length > CONSTANT_PACKET_SIZE - 2) {
            throw new Exception("Melding for stor for valgt pakkestørrelse");
        }
        
        paddedData[0] = (byte) (data.length >> 8);
        paddedData[1] = (byte) data.length;
        System.arraycopy(data, 0, paddedData, 2, data.length);

        // Krypter den polstrede bufferen
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encrypted = cipher.doFinal(paddedData);
        
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Dekrypterer og fjerner automatisk padding/støy.
     */
    public String decrypt(String encryptedBase64) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedBase64);
        
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[combined.length - 16];
        System.arraycopy(combined, 0, iv, 0, 16);
        System.arraycopy(combined, 16, encrypted, 0, encrypted.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        byte[] paddedData = cipher.doFinal(encrypted);
        
        // Les ut den faktiske lengden fra de to første bytene
        int length = ((paddedData[0] & 0xFF) << 8) | (paddedData[1] & 0xFF);
        
        return new String(Arrays.copyOfRange(paddedData, 2, 2 + length));
    }

    public String generateSignature(String data) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes()));
    }

    public boolean verifySignature(String data, String providedSignature) throws Exception {
        return generateSignature(data).equals(providedSignature);
    }
}