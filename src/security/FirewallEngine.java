package security;

import java.util.HashMap;
import java.util.Map;
import java.time.Instant;

/**
 * FirewallEngine: Håndterer dynamisk svartelisting av IP-adresser.
 * Implementerer en "Cool-off" periode for mistenkelige kilder.
 */
public class FirewallEngine {
    private static final int MAX_ATTEMPTS = 3;
    private static final long BAN_DURATION_SECONDS = 60; // 1 minutt ban for demo

    private Map<String, Integer> violationCount = new HashMap<>();
    private Map<String, Instant> bannedIps = new HashMap<>();

    /**
     * Sjekker om en IP er blokkert.
     */
    public boolean isAllowed(String ip) {
        if (bannedIps.containsKey(ip)) {
            if (Instant.now().isBefore(bannedIps.get(ip))) {
                return false; // Fortsatt bannet
            } else {
                bannedIps.remove(ip); // Ban har utløpt
                violationCount.put(ip, 0);
            }
        }
        return true;
    }

    /**
     * Registrerer et sikkerhetsbrudd for en spesifikk IP.
     */
    public void registerViolation(String ip) {
        int count = violationCount.getOrDefault(ip, 0) + 1;
        violationCount.put(ip, count);

        if (count >= MAX_ATTEMPTS) {
            bannedIps.put(ip, Instant.now().plusSeconds(BAN_DURATION_SECONDS));
            AuditLogger.logEvent("CRITICAL", "IP_BANNED", ip + " blokkert i " + BAN_DURATION_SECONDS + "s");
        } else {
            AuditLogger.logEvent("WARNING", "VIOLATION_RECORDED", ip + " har nå " + count + " brudd");
        }
    }
}