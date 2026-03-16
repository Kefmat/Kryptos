package util;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

/**
 * Utility for å generere og lagre kryptografiske nøkler.
 * Genererer AES-256 for kryptering og HMAC-SHA256 for signering.
 */
public class KeyGeneratorUtil {

    private static final String KEY_DIR = "keys/";

    /**
     * Genererer nye nøkler og lagrer dem i keys/ mappen.
     */
    public static void generateAndSaveKeys() throws Exception {
        // Opprett mappen hvis den ikke eksisterer
        Files.createDirectories(Paths.get(KEY_DIR));

        saveKeyToFile("aes_key.bin", generateKey("AES", 256));
        saveKeyToFile("hmac_key.bin", generateKey("HmacSHA256", 256));

        System.out.println("[KRYPTOS] Nye nøkler er generert og lagret i /" + KEY_DIR);
    }

    private static byte[] generateKey(String algorithm, int size) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(size);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    private static void saveKeyToFile(String fileName, byte[] key) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(KEY_DIR + fileName)) {
            fos.write(key);
        }
    }

    /**
     * Hjelpemetode for å lese nøkler senere
     */
    public static byte[] loadKeyFromFile(String fileName) throws Exception {
        return Files.readAllBytes(Paths.get(KEY_DIR + fileName));
    }
}