package security;

import java.time.Instant;

/**
 * SessionManager: Håndterer livssyklusen til kryptografiske sesjoner.
 * Sørger for automatisk reforhandling av nøkler før de utløper.
 */
public class SessionManager {
    private SecurityProvider currentProvider;
    private Instant expiry;
    private final int sessionDurationSeconds;

    public SessionManager(int durationSeconds) {
        this.sessionDurationSeconds = durationSeconds;
    }

    /**
     * Etablerer en ny sesjon
     */
    public void renegotiate() throws Exception {
        AuditLogger.logEvent("SESSION", "REKEYING", "Starter automatisk reforhandling av nøkler...");
        
        KeyExchange sideA = new KeyExchange();
        KeyExchange sideB = new KeyExchange(); 

        byte[] sharedSecret = sideA.generateSharedSecret(sideB.getPublicKeyEncoded());
        
        this.currentProvider = new SecurityProvider(sharedSecret, sharedSecret);
        this.expiry = Instant.now().plusSeconds(sessionDurationSeconds);
        
        AuditLogger.logEvent("SESSION", "ACTIVE", "Ny sesjon etablert. Utløper: " + expiry);
    }

    public boolean isExpired() {
        return expiry == null || Instant.now().isAfter(expiry);
    }

    public SecurityProvider getProvider() throws Exception {
        if (isExpired()) {
            renegotiate();
        }
        return currentProvider;
    }

    public Instant getExpiry() {
        return expiry;
    }
}