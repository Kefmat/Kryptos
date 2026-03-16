package security;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.HashSet;
import java.util.Set;

/**
 * KryptosServer: En sikker UDP-mottaker som implementerer IDS (Intrusion Detection)
 * ved å sjekke signaturer og forhindre Replay Attacks.
 */
public class KryptosServer implements Runnable {
    private int port;
    private SecurityProvider security;
    private boolean running = true;
    
    // Enkel cache for å huske brukte nonces (Anti-Replay)
    private Set<Long> usedNonces = new HashSet<>();

    public KryptosServer(int port, SecurityProvider security) {
        this.port = port;
        this.security = security;
    }

    @Override
    public void run() {
        try (DatagramSocket socket = new DatagramSocket(port)) {
            System.out.println("[KRYPTOS SERVER] Lytter på port " + port + " (SECURE MODE)");
            byte[] buffer = new byte[2048];

            while (running) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                String rawData = new String(packet.getData(), 0, packet.getLength());
                processSecurePacket(rawData);
            }
        } catch (Exception e) {
            System.err.println("[SERVER ERROR] " + e.getMessage());
        }
    }

    private void processSecurePacket(String raw) {
        try {
            // Format: nonce|signature|encryptedPayload
            String[] parts = raw.split("\\|");
            if (parts.length < 3) throw new Exception("Ugyldig pakkestruktur.");

            long nonce = Long.parseLong(parts[0]);
            String signature = parts[1];
            String payload = parts[2];

            // Anti-Replay sjekk
            if (usedNonces.contains(nonce)) {
                System.err.println("[IDS ALERT] Replay Attack detektert! Nonce " + nonce + " er allerede brukt.");
                return;
            }

            // Signaturverifisering (Integritet)
            if (!security.verifySignature(payload, signature)) {
                System.err.println("[IDS ALERT] Ugyldig signatur! Pakken kan være manipulert.");
                return;
            }

            // Dekryptering (Konfidensialitet)
            String decrypted = security.decrypt(payload);
            
            // Registrer nonce som brukt
            usedNonces.add(nonce);
            System.out.println("[KRYPTOS] Autentisert melding: " + decrypted + " (Nonce: " + nonce + ")");

        } catch (Exception e) {
            System.err.println("[KRYPTOS ERROR] Kunne ikke prosessere pakke: " + e.getMessage());
        }
    }

    public void stop() { this.running = false; }
}