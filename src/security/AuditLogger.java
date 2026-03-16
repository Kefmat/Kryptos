package security;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * AuditLogger: Ansvarlig for å logge sikkerhetskritiske hendelser.
 * Logger lagres i logs/audit.log for senere analyse.
 */
public class AuditLogger {
    private static final String LOG_FILE = "logs/audit.log";
    private static final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    static {
        // Opprett logs-mappen hvis den ikke finnes
        new java.io.File("logs").mkdirs();
    }

    /**
     * Logger en sikkerhetshendelse med alvorlighetsgrad.
     */
    public static void logEvent(String level, String event, String details) {
        String timestamp = dtf.format(LocalDateTime.now());
        String logEntry = String.format("[%s] %s | %s | %s", timestamp, level, event, details);

        System.out.println(logEntry); // Print til konsoll for sanntidsovervåking

        try (FileWriter fw = new FileWriter(LOG_FILE, true);
             PrintWriter pw = new PrintWriter(fw)) {
            pw.println(logEntry);
        } catch (IOException e) {
            System.err.println("[AUDIT ERROR] Kunne ikke skrive til logg: " + e.getMessage());
        }
    }
}