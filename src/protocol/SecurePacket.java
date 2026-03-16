package protocol;

import java.io.Serializable;

/**
 * Representerer den sikrede datapakken som sendes over nettverket.
 * Inneholder kryptert payload, kryptografisk signatur og en nonce for anti-replay.
 */
public class SecurePacket implements Serializable {
    private final String encryptedPayload; // Den AES-krypterte meldingen
    private final String signature;        // HMAC-SHA256 signaturen
    private final long nonce;              // Unikt løpenummer/tidsstempel

    public SecurePacket(String encryptedPayload, String signature, long nonce) {
        this.encryptedPayload = encryptedPayload;
        this.signature = signature;
        this.nonce = nonce;
    }

    // Gettere for validering på mottakersiden
    public String getEncryptedPayload() { return encryptedPayload; }
    public String getSignature() { return signature; }
    public long getNonce() { return nonce; }

    /**
     * Konverterer pakken til et transportvennlig format (JSON-lignende streng).
     * I en produksjonssetting ville vi brukt binær serialisering eller JSON.
     */
    @Override
    public String toString() {
        return String.format("%d|%s|%s", nonce, signature, encryptedPayload);
    }
}