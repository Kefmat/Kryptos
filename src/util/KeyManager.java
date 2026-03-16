package util;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * KeyManager: Ansvarlig for livssyklushåndtering av nøkler.
 * Implementerer rotasjonslogikk for å minimere risiko ved nøkkelkompromittering.
 */
public class KeyManager {

    private static final String KEY_DIR = "keys/";
    private static final String ARCHIVE_DIR = "keys/archive/";

    /**
     * Roterer nøkler ved å arkivere de gamle og generere nye.
     */
    public static void rotateKeys() throws Exception {
        Files.createDirectories(Paths.get(ARCHIVE_DIR));
        
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));

        // Arkiver eksisterende nøkler hvis de finnes
        archiveKey("aes_key.bin", timestamp);
        archiveKey("hmac_key.bin", timestamp);

        // Generer nye nøkler
        KeyGeneratorUtil.generateAndSaveKeys();
        System.out.println("[KEY MANAGER] Rotasjon fullført. Gamle nøkler flyttet til " + ARCHIVE_DIR);
    }

    private static void archiveKey(String fileName, String timestamp) throws Exception {
        File existingKey = new File(KEY_DIR + fileName);
        if (existingKey.exists()) {
            Files.move(existingKey.toPath(), 
                       Paths.get(ARCHIVE_DIR + timestamp + "_" + fileName), 
                       StandardCopyOption.REPLACE_EXISTING);
        }
    }
}