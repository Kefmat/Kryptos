package security;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.HashSet;
import java.util.Set;

/**
 * KryptosServer: En sikker UDP-mottaker som implementerer IDS (Intrusion Detection)
 * og Audit Logging for alle innkommende forespørsler.
 */
public class KryptosServer implements Runnable {
    private int port;
    private SecurityProvider security;
    private boolean running = true;
    private Set<Long> usedNonces = new HashSet<>();

    public KryptosServer(int port, SecurityProvider security) {
        this.port = port;
        this.security = security;
    }

    @Override
    public void run() {
        try (DatagramSocket socket = new DatagramSocket(port)) {
            AuditLogger.logEvent("INFO", "SERVER_START", "Lytter på port " + port);
            byte[] buffer = new byte[2048];

            while (running) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                String sourceIp = packet.getAddress().getHostAddress();
                String rawData = new String(packet.getData(), 0, packet.getLength());
                
                processSecurePacket(rawData, sourceIp);
            }
        } catch (Exception e) {
            AuditLogger.logEvent("CRITICAL", "SERVER_CRASH", e.getMessage());
        }
    }

    private void processSecurePacket(String raw, String sourceIp) {
        try {
            String[] parts = raw.split("\\|");
            if (parts.length < 3) {
                AuditLogger.logEvent("WARNING", "MALFORMED_PACKET", "Fra: " + sourceIp);
                return;
            }

            long nonce = Long.parseLong(parts[0]);
            String signature = parts[1];
            String payload = parts[2];

            // Anti-Replay sjekk
            if (usedNonces.contains(nonce)) {
                AuditLogger.logEvent("ALERT", "REPLAY_ATTACK", "IP: " + sourceIp + " | Nonce: " + nonce);
                return;
            }

            // Signaturverifisering
            if (!security.verifySignature(payload, signature)) {
                AuditLogger.logEvent("ALERT", "INVALID_SIGNATURE", "IP: " + sourceIp + " | Payload manipulert");
                return;
            }

            // Dekryptering
            String decrypted = security.decrypt(payload);
            usedNonces.add(nonce);
            
            AuditLogger.logEvent("INFO", "AUTHORIZED_CMD", "Kommando: " + decrypted);

        } catch (Exception e) {
            AuditLogger.logEvent("ERROR", "PROCESSING_FAILED", sourceIp + ": " + e.getMessage());
        }
    }

    public void stop() { this.running = false; }
}